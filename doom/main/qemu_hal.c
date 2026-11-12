// SPDX-License-Identifier: MIT
//
// m5_hal.h implemented for Espressif's QEMU (CONFIG_DOOM_QEMU): frames go to
// the emulator's virtual RGB panel, audio is consumed at real-time pace and
// discarded, and input comes from a fixed script that boots into E1M1 and
// exercises each control. The script advances a step only once that step has
// lasted its minimum time AND been seen by enough input reads, so a slow
// emulated frame rate cannot make the game miss a press or a release.

#include "m5_hal.h"

#include <doomstat.h>
#include <p_inter.h>
#include <p_mobj.h>
#include <tables.h>
#include <info.h>
#include <m_fixed.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_timer.h>

static const char *TAG = "qemu_hal";

// Espressif QEMU's virtual RGB panel (hw/display/esp_rgb.c), driven
// directly. Its registry driver, espressif/esp_lcd_qemu_rgb, spins after
// every draw until a display backend consumes the frame; with -nographic
// nothing ever does. Here a frame is written into the panel's VRAM and
// marked dirty, and QEMU copies it out whenever its display (or a monitor
// `screendump`) next updates.
typedef volatile struct {
    uint32_t version;
    uint32_t size;          // width << 16 | height
    uint32_t update_from;   // x << 16 | y
    uint32_t update_to;     // x << 16 | y, exclusive
    const void *update_content;
    uint32_t update_st;     // bit 0: update pending
    uint32_t bpp;
} rgb_qemu_regs_t;

static rgb_qemu_regs_t *const rgb = (rgb_qemu_regs_t *)0x21000000;
static uint16_t *const fb = (uint16_t *)0x20000000;   // panel VRAM

static void panel_refresh(void)
{
    rgb->update_from = 0;
    rgb->update_to = (uint32_t)HAL_SCREEN_W << 16 | HAL_SCREEN_H;
    rgb->update_content = fb;
    rgb->update_st = 1;
}

// ---- Input script ---------------------------------------------------------

enum { A = 1, B = 2, C = 4 };

typedef struct {
    uint8_t buttons;     // A | B | C held during this step
    bool touch;          // finger on the screen at the centre
    float tilt_x, tilt_y;
    int min_ms;          // step lasts at least this long...
    int min_reads;       // ...and at least this many hal_input_read calls
    const char *shot;    // if set, announce a screenshot once a frame is drawn
    const char *note;
    int damage;          // if set, deal this much damage to the player on entry
    bool spawn;          // if set, spawn a zombieman 128 units ahead on entry
} step_t;

static const step_t script[] = {
    {0, false, 0, 0, 1500, 10, "01-title", "title screen / demo"},
    {B, false, 0, 0, 150, 3, NULL, "any key opens the menu"},
    {0, false, 0, 0, 800, 3, "02-main-menu", NULL},
    {B, false, 0, 0, 150, 3, NULL, "New Game"},
    {0, false, 0, 0, 600, 3, NULL, NULL},
    {B, false, 0, 0, 150, 3, NULL, "Knee-Deep in the Dead"},
    {0, false, 0, 0, 600, 3, "03-skill-menu", NULL},
    {B, false, 0, 0, 150, 3, NULL, "Hurt Me Plenty"},
    {0, false, 0, 0, 2500, 20, "04-e1m1-start", "level loaded"},
    {0, false, 0, 0, 600, 10, "04b-zombieman", "spawn a zombieman ahead (test injection)", 0, true},
    {0, true, 0, 0, 2500, 40, NULL, "touch: shoot the zombieman"},
    {0, false, 0, 0, 600, 10, "04c-zombieman-shot", NULL},
    {0, false, 0, 0.30f, 2000, 30, NULL, "tilt forward: walk"},
    {0, false, 0, 0, 300, 3, "05-after-walk", NULL},
    {0, true, 0, 0, 200, 3, "06-firing", "touch: fire"},
    {0, true, 0, 0, 800, 10, NULL, NULL},
    {0, false, 0, 0, 300, 3, NULL, NULL},
    {0, false, 0.30f, 0, 1200, 20, NULL, "tilt right: turn"},
    {0, false, 0, 0, 300, 3, "07-after-turn", NULL},
    {0, false, 0, 0, 800, 10, NULL, "take 15 damage (test injection)", 15},
    {0, false, 0, 0, 300, 3, "07c-hurt", NULL},
    {B, false, 0, 0, 150, 3, NULL, "B: weapon toggle (pistol to fist)"},
    {0, false, 0, 0, 300, 3, NULL, NULL},
    {C, false, 0, 0, 150, 3, NULL, "C tap: automap"},
    {0, false, 0, 0, 800, 5, "08-automap", NULL},
    {C, false, 0, 0, 150, 3, NULL, "C tap: automap off"},
    {0, false, 0, 0, 500, 3, NULL, NULL},
    {C, false, 0, 0, 800, 5, NULL, "C hold: menu"},
    {0, false, 0, 0, 800, 3, "09-ingame-menu", NULL},
    {C, false, 0, 0, 150, 3, NULL, "C tap in menu: down"},
    {0, false, 0, 0, 500, 3, "10-menu-down", NULL},
};
#define SCRIPT_LEN (sizeof(script) / sizeof(script[0]))

static int step = -1;
static int64_t step_start_ms;
static int step_reads;
static const char *pending_shot;
static bool shot_taken;
static bool script_done;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static void script_enter(int i)
{
    step = i;
    step_start_ms = now_ms();
    step_reads = 0;
    if (i < (int)SCRIPT_LEN && script[i].note)
        printf("SCRIPT %d: %s\n", i, script[i].note);
    mobj_t *pmo = players[consoleplayer].mo;
    if (i < (int)SCRIPT_LEN && script[i].damage && pmo)
        P_DamageMobj(pmo, NULL, NULL, script[i].damage);
    if (i < (int)SCRIPT_LEN && script[i].spawn && pmo)
    {
        unsigned an = pmo->angle >> ANGLETOFINESHIFT;
        P_SpawnMobj(pmo->x + FixedMul(128 * FRACUNIT, finecosine[an]),
                    pmo->y + FixedMul(128 * FRACUNIT, finesine[an]),
                    ONFLOORZ, MT_POSSESSED);
    }
}

// ---- HAL ------------------------------------------------------------------

void hal_init(void)
{
    rgb->size = (uint32_t)HAL_SCREEN_W << 16 | HAL_SCREEN_H;
    rgb->bpp = 16;
    memset(fb, 0, HAL_SCREEN_W * HAL_SCREEN_H * 2);
    panel_refresh();
    ESP_LOGI(TAG, "virtual panel v%08lx %dx%d RGB565", (unsigned long)rgb->version,
             HAL_SCREEN_W, HAL_SCREEN_H);
}

void hal_display_frame(const uint8_t *src, const uint16_t *palette_be, int w, int h)
{
    static int frames;
    static int64_t fps_start;
    int y0 = (HAL_SCREEN_H - h) / 2;
    uint16_t *dst = fb + y0 * HAL_SCREEN_W;

    // The palette is byte-swapped for the Core2's SPI panel; QEMU's panel
    // takes native-endian RGB565.
    for (int i = 0, n = w * h; i < n; i++)
    {
        uint16_t c = palette_be[src[i]];
        dst[i] = c << 8 | c >> 8;
    }
    panel_refresh();

    if (pending_shot)
    {
        // Freeze on this frame until the harness has dumped the screen and
        // sends '!' back over the UART, so the capture matches the label.
        printf("SHOT %s\n", pending_shot);
        fflush(stdout);
        int64_t give_up = now_ms() + 30000;
        char c = 0;
        while (c != '!' && now_ms() < give_up)
        {
            if (read(STDIN_FILENO, &c, 1) != 1)
                vTaskDelay(pdMS_TO_TICKS(10));
        }
        pending_shot = NULL;
        shot_taken = true;
        fps_start = now_ms();
        frames = 0;
    }

    int64_t t = now_ms();
    if (!fps_start)
        fps_start = t;
    if (++frames == 100)
    {
        printf("FPS %.1f (emulated, not representative of hardware)\n",
               frames * 1000.0 / (t - fps_start));
        frames = 0;
        fps_start = t;
    }
}

void hal_display_text(const char *msg)
{
    memset(fb, 0, HAL_SCREEN_W * HAL_SCREEN_H * 2);
    panel_refresh();
    ESP_LOGI(TAG, "screen text: %s", msg);
}

void hal_input_read(hal_input_t *in)
{
    memset(in, 0, sizeof(*in));
    in->imu_ok = true;
    in->az = 1.0f;   // lying flat, screen up: the neutral pose

    if (script_done)
        return;

    if (step < 0)
        script_enter(0);

    const step_t *s = &script[step];
    step_reads++;

    if (!pending_shot && step_reads >= s->min_reads && now_ms() - step_start_ms >= s->min_ms)
    {
        // A step with a shot holds its input until the shot is taken, so
        // the next step's presses cannot reach the captured frame.
        if (s->shot && !shot_taken)
        {
            pending_shot = s->shot;
            goto deliver;
        }
        shot_taken = false;
        if (step + 1 >= (int)SCRIPT_LEN)
        {
            printf("SCRIPT DONE\n");
            script_done = true;
            return;
        }
        script_enter(step + 1);
        s = &script[step];
    }

deliver:
    in->btn_a = s->buttons & A;
    in->btn_b = s->buttons & B;
    in->btn_c = s->buttons & C;
    in->touching = s->touch;
    in->touch_x = HAL_SCREEN_W / 2;
    in->touch_y = HAL_SCREEN_H / 2;
    in->ax = s->tilt_x;
    in->ay = s->tilt_y;
}

// ---- Vibration: logged ----------------------------------------------------

void hal_vibrate(uint8_t level)
{
    printf("VIB %u t=%lld\n", level, (long long)now_ms());
}

// ---- Audio: counted and discarded -----------------------------------------

static int sfx_count;

bool hal_sfx_play(int channel, const uint8_t *data, size_t len, uint32_t rate, uint8_t volume)
{
    if (++sfx_count % 10 == 1)
        printf("SFX #%d ch%d len=%u rate=%u vol=%u\n", sfx_count, channel,
               (unsigned)len, (unsigned)rate, volume);
    return true;
}

void hal_sfx_volume(int channel, uint8_t volume) {}
void hal_sfx_stop(int channel) {}
bool hal_sfx_playing(int channel) { return false; }

bool hal_music_play(const int16_t *stereo, size_t frames, uint32_t rate)
{
    static int chunks;
    if (++chunks % 350 == 1)
    {
        int peak = 0;
        for (size_t i = 0; i < frames * 2; i++)
            peak = stereo[i] > peak ? stereo[i] : (-stereo[i] > peak ? -stereo[i] : peak);
        printf("MUSIC chunk #%d peak=%d\n", chunks, peak);
    }
    // Consume at playback speed, as the speaker would
    vTaskDelay(pdMS_TO_TICKS(frames * 1000 / rate));
    return true;
}

int hal_music_queued(void) { return 0; }
