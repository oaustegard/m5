// SPDX-License-Identifier: MIT
#include "m5_hal.h"

#include <M5Unified.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <math.h>
#include <stdio.h>

// The frame goes out in horizontal bands through two DMA buffers: one is
// converted from palette indices while the other is on the SPI bus.
// pushImageDMA waits for the previous transfer before starting the next,
// so a buffer is free again by the time the loop comes back to it.
#define BAND_LINES 20

#define SPEAKER_VOLUME 160

static uint16_t *band[2];

extern "C" void hal_init(void)
{
    auto cfg = M5.config();
    cfg.internal_imu = true;
    cfg.internal_spk = true;
    cfg.internal_mic = false;   // shares the I2S peripheral with the speaker
    M5.begin(cfg);

    // M5Unified's default rotation for the Core2 is already 320x240
    // landscape; setRotation(1) turned the picture 90 degrees.
    printf("m5: display rotation %d, %dx%d\n", (int)M5.Display.getRotation(),
           (int)M5.Display.width(), (int)M5.Display.height());
    M5.Display.fillScreen(TFT_BLACK);

    auto spk = M5.Speaker.config();
    spk.task_pinned_core = 1;   // Doom's game loop runs on core 0
    spk.dma_buf_count = 8;
    spk.dma_buf_len = 256;
    M5.Speaker.config(spk);
    M5.Speaker.begin();
    M5.Speaker.setVolume(SPEAKER_VOLUME);

    for (int i = 0; i < 2; i++)
        band[i] = (uint16_t *)heap_caps_malloc(HAL_SCREEN_W * BAND_LINES * sizeof(uint16_t),
                                               MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
}

extern "C" void hal_display_frame(const uint8_t *fb, const uint16_t *palette_be, int w, int h)
{
    int y0 = (HAL_SCREEN_H - h) / 2;
    int b = 0;

    M5.Display.startWrite();
    for (int y = 0; y < h; y += BAND_LINES, b ^= 1)
    {
        int lines = (h - y) < BAND_LINES ? (h - y) : BAND_LINES;
        const uint8_t *src = fb + y * w;
        uint16_t *dst = band[b];
        for (int i = 0, n = lines * w; i < n; i++)
            dst[i] = palette_be[src[i]];
        M5.Display.pushImageDMA(0, y0 + y, w, lines, (const lgfx::swap565_t *)dst);
    }
    M5.Display.waitDMA();
    M5.Display.endWrite();
}

extern "C" void hal_display_text(const char *msg)
{
    M5.Display.fillScreen(TFT_BLACK);
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.setTextDatum(middle_center);
    M5.Display.setTextSize(2);
    M5.Display.drawString(msg, HAL_SCREEN_W / 2, HAL_SCREEN_H / 2);
}

extern "C" void hal_input_read(hal_input_t *in)
{
    M5.update();

    in->btn_a = M5.BtnA.isPressed();
    in->btn_b = M5.BtnB.isPressed();
    in->btn_c = M5.BtnC.isPressed();
    in->btn_pwr_click = M5.BtnPWR.wasClicked();

    in->touching = false;
    for (int i = 0, n = M5.Touch.getCount(); i < n; i++)
    {
        const auto &t = M5.Touch.getDetail(i);
        if (t.isPressed() && t.y >= 0 && t.y < HAL_SCREEN_H)
        {
            in->touching = true;
            in->touch_x = t.x;
            in->touch_y = t.y;
        }
    }

    in->imu_ok = false;
    if (M5.Imu.isEnabled())
    {
        M5.Imu.update();
        in->imu_ok = M5.Imu.getAccel(&in->ax, &in->ay, &in->az);
    }
}

// ---- Boot setup screen ----------------------------------------------------

#define LEVEL_SIZE   164                // sprite side, px
#define LEVEL_R      (LEVEL_SIZE / 2 - 2)
#define LEVEL_X      8                  // sprite position on screen
#define LEVEL_Y      58
#define LEVEL_FULL_R 68                 // radius of the full-speed ring, px
#define DOT_R        6

static void draw_setup_text(bool imu_ok)
{
    auto &d = M5.Display;
    d.fillScreen(TFT_BLACK);
    d.setTextDatum(top_left);
    d.setFont(&fonts::Font2);
    d.setTextSize(1);

    d.setTextColor(TFT_YELLOW, TFT_BLACK);
    d.drawString("Hold the Core2 the way you want to play,", 6, 6);
    d.drawString("then tap the screen", 6, 24);

    static const char *const lines[][2] = {
        {"Tilt", "move / turn"},
        {"Touch", "fire"},
        {"A", "use"},
        {"", "hold: re-centre"},
        {"B", "weapon"},
        {"C", "map"},
        {"", "hold: menu"},
        {"Dead?", "tap to restart"},
        {"Power", "mute / unmute"},
        {"Menus", "tilt, or tap twice"},
    };
    int y = 48;
    for (const auto &l : lines)
    {
        d.setTextColor(TFT_ORANGE, TFT_BLACK);
        d.drawString(l[0], 184, y);
        d.setTextColor(TFT_WHITE, TFT_BLACK);
        d.drawString(l[1], l[0][0] ? 232 : 196, y);
        y += 17;
    }

    d.setTextColor(TFT_DARKGREY, TFT_BLACK);
    d.drawString(imu_ok ? "dot = tilt, rings = dead zone / full speed"
                        : "no motion sensor: tilt is off",
                 6, 222);
}

extern "C" bool hal_setup_screen(const hal_setup_t *cfg, float *neutral_x, float *neutral_y)
{
    hal_input_t in;
    hal_input_read(&in);
    bool imu_ok = in.imu_ok;
    draw_setup_text(imu_ok);

    M5Canvas level(&M5.Display);
    level.setPsram(false);
    bool have_sprite = level.createSprite(LEVEL_SIZE, LEVEL_SIZE) != nullptr;

    const float scale = LEVEL_FULL_R / cfg->full;          // px per g
    const int dead_r = (int)(cfg->deadzone * scale + 0.5f);
    const int c = LEVEL_SIZE / 2;

    // Until the tap, the dot is drawn against the pose at power-on, so it
    // shows how the controls would read if that were the neutral pose.
    float ref_x = in.ax, ref_y = in.ay;
    float fx = in.ax, fy = in.ay;
    bool was_touching = in.touching;     // ignore a finger already down at boot
    bool captured = false;

    for (;;)
    {
        int64_t frame_start = esp_timer_get_time();
        hal_input_read(&in);

        if (in.imu_ok)
        {
            fx += 0.35f * (in.ax - fx);
            fy += 0.35f * (in.ay - fy);
        }

        if (in.touching && !was_touching)
        {
            *neutral_x = fx;
            *neutral_y = fy;
            ref_x = fx;
            ref_y = fy;
            captured = in.imu_ok;
        }
        if (!in.touching && was_touching && (captured || !imu_ok))
            break;
        was_touching = in.touching;

        if (have_sprite)
        {
            float dx = cfg->dot_x_per_ax * (fx - ref_x);
            float dy = cfg->dot_y_per_ay * (fy - ref_y);
            float mx = fabsf(dx), my = fabsf(dy);
            float m = mx > my ? mx : my;   // the game reads each axis separately
            uint16_t dot = m < cfg->deadzone ? TFT_DARKGREY
                         : m < cfg->full     ? TFT_YELLOW
                                             : TFT_RED;
            int px = (int)(dx * scale), py = (int)(dy * scale);
            int lim = LEVEL_R - DOT_R;
            float len = sqrtf((float)(px * px + py * py));
            if (len > lim)
            {
                px = (int)(px * lim / len);
                py = (int)(py * lim / len);
            }

            level.fillSprite(TFT_BLACK);
            level.drawCircle(c, c, LEVEL_R, TFT_DARKGREY);
            level.drawCircle(c, c, LEVEL_FULL_R, TFT_WHITE);
            level.drawCircle(c, c, dead_r, TFT_DARKGREY);
            level.drawFastHLine(c - LEVEL_R, c, 2 * LEVEL_R, 0x2104);
            level.drawFastVLine(c, c - LEVEL_R, 2 * LEVEL_R, 0x2104);
            if (in.touching)
                level.drawCircle(c, c, dead_r + 3, TFT_GREEN);
            if (imu_ok)
                level.fillCircle(c + px, c + py, DOT_R, dot);
            level.pushSprite(LEVEL_X, LEVEL_Y);
        }

        int64_t spent_ms = (esp_timer_get_time() - frame_start) / 1000;
        if (spent_ms < 33)
            vTaskDelay(pdMS_TO_TICKS(33 - spent_ms));
    }

    if (have_sprite)
        level.deleteSprite();
    printf("m5: setup done, neutral %s %.3f,%.3f\n", captured ? "set" : "unset",
           captured ? *neutral_x : 0.0f, captured ? *neutral_y : 0.0f);
    return captured;
}

extern "C" void hal_set_muted(bool muted)
{
    M5.Speaker.setVolume(muted ? 0 : SPEAKER_VOLUME);
}

extern "C" void hal_vibrate(uint8_t level)
{
    // AXP192 LDO3 on the original Core2, AXP2101 DLDO1 on v1.1;
    // M5Unified maps the level to a rail voltage (255 is about 3.5 V).
    M5.Power.setVibration(level);
}

extern "C" bool hal_sfx_play(int channel, const uint8_t *data, size_t len, uint32_t rate, uint8_t volume)
{
    M5.Speaker.setChannelVolume(channel, volume);
    return M5.Speaker.playRaw(data, len, rate, false, 1, channel, true);
}

extern "C" void hal_sfx_volume(int channel, uint8_t volume)
{
    M5.Speaker.setChannelVolume(channel, volume);
}

extern "C" void hal_sfx_stop(int channel)
{
    M5.Speaker.stop(channel);
}

extern "C" bool hal_sfx_playing(int channel)
{
    return M5.Speaker.isPlaying(channel) > 0;
}

extern "C" bool hal_music_play(const int16_t *stereo, size_t frames, uint32_t rate)
{
    return M5.Speaker.playRaw(stereo, frames * 2, rate, true, 1, 0, false);
}

extern "C" int hal_music_queued(void)
{
    return (int)M5.Speaker.isPlaying(0);
}
