// SPDX-License-Identifier: GPL-3.0-only
/*
 * PrBoom platform layer for the M5Stack Core2.
 *
 * Adapted from retro-go's prboom-go/main/main.c (Copyright (c) 2019 ducalex,
 * GPL-3.0), with retro-go's system layer replaced by M5Unified (m5_hal.cpp),
 * flash FAT partitions for WADs and saves, and tilt + touch controls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <unistd.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_timer.h>
#include <esp_heap_caps.h>
#include <esp_system.h>
#include <esp_vfs_fat.h>

#include <doomtype.h>
#include <doomstat.h>
#include <doomdef.h>
#include <d_main.h>
#include <g_game.h>
#include <i_system.h>
#include <i_video.h>
#include <i_sound.h>
#include <i_main.h>
#include <m_argv.h>
#include <m_fixed.h>
#include <m_misc.h>
#include <r_draw.h>
#include <r_fps.h>
#include <s_sound.h>
#include <st_stuff.h>
#include <sounds.h>
#include <w_wad.h>
#include <z_zone.h>
#include <v_video.h>
#include <mus2mid.h>
#include <midifile.h>
#include <oplplayer.h>
#include <lprintf.h>

#include "m5_hal.h"

#define WAD_DIR  "/wads"
#define SAVE_DIR "/saves"
#define IWAD     WAD_DIR "/DOOM1.WAD"

#define AUDIO_SAMPLE_RATE 22050
#define MUSIC_FRAMES (AUDIO_SAMPLE_RATE / TICRATE + 1)

// ---- Tilt tuning ----------------------------------------------------------
// Deltas are in g from the neutral pose captured at boot (or on a long press
// of button A). Signs depend on how the IMU sits on the board; flip these if
// tilting goes the wrong way.
#define TILT_DEADZONE   0.08f
#define TILT_FULL       0.35f
#define TILT_TURN_SIGN  (-1)   // applied to the x-axis delta
#define TILT_MOVE_SIGN  (+1)   // applied to the y-axis delta
#define TILT_MAX_TURN   1280   // angleturn units per tic (fast turn)
#define TILT_MAX_MOVE   50     // forwardmove units per tic (run speed)

#define LONG_PRESS_MS   500
#define RECAL_PRESS_MS  1200

// Expected by the engine
int snd_card = 1, mus_card = 1;
int snd_samplerate = AUDIO_SAMPLE_RATE;
int current_palette = 0;

static uint8_t *framebuffer;
static uint16_t palette_be[256];

static const char *doom_argv[8];

// ---- Video ----------------------------------------------------------------

void I_StartFrame(void) {}
void I_UpdateNoBlit(void) {}
bool I_StartDisplay(void) { return true; }
void I_EndDisplay(void) {}

void I_FinishUpdate(void)
{
    hal_display_frame(framebuffer, palette_be, SCREENWIDTH, SCREENHEIGHT);
}

void I_SetPalette(int pal)
{
    uint16_t *palette = V_BuildPalette(pal, 16);
    for (int i = 0; i < 256; i++)
        palette_be[i] = palette[i] << 8 | palette[i] >> 8;
    Z_Free(palette);
    current_palette = pal;
}

void I_InitGraphics(void)
{
    for (int i = 0; i < 3; i++)
    {
        screens[i].width = SCREENWIDTH;
        screens[i].height = SCREENHEIGHT;
        screens[i].byte_pitch = SCREENWIDTH;
    }

    // The main screen lives in internal RAM for speed
    screens[0].data = framebuffer;
    screens[0].not_on_heap = true;

    // Status bar
    screens[4].width = SCREENWIDTH;
    screens[4].height = (ST_SCALED_HEIGHT + 1);
    screens[4].byte_pitch = SCREENWIDTH;
}

// ---- System ---------------------------------------------------------------

int I_GetTimeMS(void)
{
    return esp_timer_get_time() / 1000;
}

int I_GetTime(void)
{
    return I_GetTimeMS() * TICRATE * realtic_clock_rate / 100000;
}

void I_uSleep(unsigned long usecs)
{
    usleep(usecs);
}

void I_SafeExit(int rc)
{
    esp_restart();
}

const char *I_DoomExeDir(void)
{
    return SAVE_DIR;
}

// ---- Sound effects --------------------------------------------------------

typedef struct {
    const uint8_t *samples;
    size_t length;
    uint16_t rate;
} sfx_t;

static sfx_t sfx[NUMSFX];
static int sfx_starttic[HAL_SFX_CHANNELS];

static uint8_t sfx_volume(int vol)
{
    // The engine passes 0..127, already scaled by the SFX volume setting
    int v = vol * 2;
    return v > 255 ? 255 : (v < 0 ? 0 : v);
}

int I_StartSound(int sfxid, int channel, int vol, int sep, int pitch, int priority)
{
    if (sfxid <= 0 || sfxid >= NUMSFX || !sfx[sfxid].samples)
        return -1;

    int slot = -1;
    int oldest = gametic;

    for (int i = 0; i < HAL_SFX_CHANNELS; i++)
    {
        if (!hal_sfx_playing(i + 1))
        {
            slot = i;
            break;
        }
        if (sfx_starttic[i] <= oldest)
        {
            slot = i;
            oldest = sfx_starttic[i];
        }
    }

    sfx_starttic[slot] = gametic;
    hal_sfx_play(slot + 1, sfx[sfxid].samples, sfx[sfxid].length, sfx[sfxid].rate, sfx_volume(vol));
    return slot;
}

void I_UpdateSoundParams(int handle, int vol, int sep, int pitch)
{
    if (handle >= 0 && handle < HAL_SFX_CHANNELS)
        hal_sfx_volume(handle + 1, sfx_volume(vol));
}

void I_StopSound(int handle)
{
    if (handle >= 0 && handle < HAL_SFX_CHANNELS)
        hal_sfx_stop(handle + 1);
}

bool I_SoundIsPlaying(int handle)
{
    // Same as retro-go: the engine frees its channel bookkeeping right away
    return false;
}

bool I_AnySoundStillPlaying(void)
{
    for (int i = 0; i < HAL_SFX_CHANNELS; i++)
        if (hal_sfx_playing(i + 1))
            return true;
    return false;
}

// ---- Music ----------------------------------------------------------------

static const music_player_t *music_player = &opl_synth_player;
static volatile bool music_playing = false;

static void music_task(void *arg)
{
    // Three buffers: one playing, one queued, one being rendered
    static int16_t buffers[3][MUSIC_FRAMES * 2];
    int next = 0;

    while (1)
    {
        if (!music_playing || snd_MusicVolume == 0)
        {
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        while (hal_music_queued() >= 2)
            vTaskDelay(1);

        music_player->render(buffers[next], MUSIC_FRAMES);
        hal_music_play(buffers[next], MUSIC_FRAMES, AUDIO_SAMPLE_RATE);
        next = (next + 1) % 3;
    }
}

void I_InitSound(void)
{
    for (int i = 1; i < NUMSFX; i++)
    {
        if (S_sfx[i].lumpnum == -1)
            continue;

        // DMX sound lump: u16 format, u16 rate, u32 length, then samples
        // padded with 16 bytes on each side.
        const uint8_t *lump = W_CacheLumpNum(S_sfx[i].lumpnum);
        size_t lumplen = W_LumpLength(S_sfx[i].lumpnum);
        if (lumplen < 8)
            continue;

        uint32_t length = lump[4] | lump[5] << 8 | lump[6] << 16 | (uint32_t)lump[7] << 24;
        if (length > lumplen - 8)
            length = lumplen - 8;

        const uint8_t *samples = lump + 8;
        if (length > 32)
        {
            samples += 16;
            length -= 32;
        }

        sfx[i].samples = samples;
        sfx[i].length = length;
        sfx[i].rate = lump[2] | lump[3] << 8;
    }

    music_player->init(snd_samplerate);
    music_player->setvolume(snd_MusicVolume);

    xTaskCreatePinnedToCore(music_task, "doom_music", 3072, NULL, 5, NULL, 1);
}

void I_ShutdownSound(void)
{
    music_player->shutdown();
}

void I_PlaySong(int handle, int looping)
{
    music_player->play((void *)handle, looping);
    music_playing = true;
}

void I_PauseSong(int handle)
{
    music_player->pause();
    music_playing = false;
}

void I_ResumeSong(int handle)
{
    music_player->resume();
    music_playing = true;
}

void I_StopSong(int handle)
{
    music_player->stop();
    music_playing = false;
}

void I_UnRegisterSong(int handle)
{
    music_player->unregistersong((void *)handle);
}

int I_RegisterSong(const void *data, size_t len)
{
    uint8_t *mid = NULL;
    size_t midlen;
    int handle;

    if (mus2mid(data, len, &mid, &midlen, 64) == 0)
        handle = (int)music_player->registersong(mid, midlen);
    else
        handle = (int)music_player->registersong(data, len);

    free(mid);
    return handle;
}

void I_SetMusicVolume(int volume)
{
    music_player->setvolume(volume);
}

// ---- Input ----------------------------------------------------------------
//
// In game:   tilt = move/turn, touch screen = fire,
//            A = use (hold 1.2 s: re-centre tilt), B = next weapon,
//            C = automap (hold: menu).
// In menus:  A = up, C = down (hold: back), B = select,
//            touch left/right third = slider left/right, middle = select.

enum { BTN_A, BTN_B, BTN_C, BTN_TOUCH, BTN_COUNT };

static float neutral_x, neutral_y;
static bool neutral_set = false;

static void post_key(evtype_t type, int key)
{
    event_t ev = {0};
    ev.type = type;
    ev.data1 = key;
    D_PostEvent(&ev);
}

static float tilt_axis(float delta)
{
    float mag = fabsf(delta);
    if (mag < TILT_DEADZONE)
        return 0.0f;
    float v = (mag - TILT_DEADZONE) / (TILT_FULL - TILT_DEADZONE);
    if (v > 1.0f)
        v = 1.0f;
    return delta < 0 ? -v : v;
}

static int key_for(int button, bool in_menu, int touch_x)
{
    if (in_menu)
    {
        switch (button)
        {
        case BTN_A: return key_menu_up;
        case BTN_B: return key_enter;
        case BTN_C: return key_menu_down;
        case BTN_TOUCH:
            if (touch_x < HAL_SCREEN_W / 3)
                return key_menu_left;
            if (touch_x > HAL_SCREEN_W * 2 / 3)
                return key_menu_right;
            return key_enter;
        }
    }
    else
    {
        switch (button)
        {
        case BTN_A: return key_use;
        case BTN_B: return key_weapontoggle;
        case BTN_C: return key_map;
        case BTN_TOUCH: return key_fire;
        }
    }
    return 0;
}

void I_StartTic(void)
{
    static bool prev[BTN_COUNT];
    static int held_key[BTN_COUNT];
    static int64_t press_ms[BTN_COUNT];
    static bool long_fired[BTN_COUNT];

    hal_input_t in;
    hal_input_read(&in);

    bool now[BTN_COUNT] = {in.btn_a, in.btn_b, in.btn_c, in.touching};
    bool in_menu = menuactive;
    int64_t t = esp_timer_get_time() / 1000;

    for (int b = 0; b < BTN_COUNT; b++)
    {
        if (now[b] && !prev[b])
        {
            press_ms[b] = t;
            long_fired[b] = false;

            // C waits to tell a tap from a hold; everything else acts at once
            if (b != BTN_C)
            {
                held_key[b] = key_for(b, in_menu, in.touch_x);
                post_key(ev_keydown, held_key[b]);
            }
        }
        else if (now[b] && prev[b] && !long_fired[b])
        {
            if (b == BTN_C && t - press_ms[b] >= LONG_PRESS_MS)
            {
                post_key(ev_keydown, key_escape);
                post_key(ev_keyup, key_escape);
                long_fired[b] = true;
            }
            else if (b == BTN_A && !in_menu && t - press_ms[b] >= RECAL_PRESS_MS && in.imu_ok)
            {
                neutral_x = in.ax;
                neutral_y = in.ay;
                neutral_set = true;
                long_fired[b] = true;
            }
        }
        else if (!now[b] && prev[b])
        {
            if (b == BTN_C)
            {
                if (!long_fired[b])
                {
                    int key = key_for(b, in_menu, in.touch_x);
                    post_key(ev_keydown, key);
                    post_key(ev_keyup, key);
                }
            }
            else
            {
                post_key(ev_keyup, held_key[b]);
            }
        }
        prev[b] = now[b];
    }

    analog_turn = 0;
    analog_forward = 0;

    if (in.imu_ok)
    {
        if (!neutral_set)
        {
            neutral_x = in.ax;
            neutral_y = in.ay;
            neutral_set = true;
        }
        if (!in_menu && gamestate == GS_LEVEL)
        {
            analog_turn = (int)(TILT_TURN_SIGN * tilt_axis(in.ax - neutral_x) * TILT_MAX_TURN);
            analog_forward = (int)(TILT_MOVE_SIGN * tilt_axis(in.ay - neutral_y) * TILT_MAX_MOVE);
        }
    }
}

void I_Init(void)
{
    snd_channels = HAL_SFX_CHANNELS;
    snd_samplerate = AUDIO_SAMPLE_RATE;
    snd_MusicVolume = 8;
    snd_SfxVolume = 15;
}

// ---- Boot -----------------------------------------------------------------

static void mount_filesystems(void)
{
    const esp_vfs_fat_mount_config_t ro = {
        .max_files = 4,
        .format_if_mount_failed = false,
    };
    ESP_ERROR_CHECK(esp_vfs_fat_spiflash_mount_ro(WAD_DIR, "wads", &ro));

    const esp_vfs_fat_mount_config_t rw = {
        .max_files = 4,
        .format_if_mount_failed = true,
        .allocation_unit_size = 4096,
    };
    static wl_handle_t wl = WL_INVALID_HANDLE;
    ESP_ERROR_CHECK(esp_vfs_fat_spiflash_mount_rw_wl(SAVE_DIR, "saves", &rw, &wl));
}

void app_main(void)
{
    hal_init();
    hal_display_text("Loading DOOM...");

    mount_filesystems();

    SCREENWIDTH = HAL_SCREEN_W < MAX_SCREENWIDTH ? HAL_SCREEN_W : MAX_SCREENWIDTH;
    SCREENHEIGHT = HAL_SCREEN_H < MAX_SCREENHEIGHT ? HAL_SCREEN_H : MAX_SCREENHEIGHT;

    framebuffer = heap_caps_malloc(SCREENWIDTH * SCREENHEIGHT, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!framebuffer)
        I_Error("Framebuffer allocation failed");

    myargv = doom_argv;
    myargc = 5;
    doom_argv[0] = "doom";
    doom_argv[1] = "-save";
    doom_argv[2] = SAVE_DIR;
    doom_argv[3] = "-iwad";
    doom_argv[4] = IWAD;
    doom_argv[5] = NULL;

    // Everything allocated from here on (zone heap, lump cache) prefers PSRAM;
    // the framebuffer and DMA buffers above already sit in internal RAM.
    heap_caps_malloc_extmem_enable(0);

    Z_Init();
    D_DoomMain();
}
