// SPDX-License-Identifier: MIT
// Thin C interface over M5Unified for the Core2, so the Doom platform layer
// (plain C, like the engine) never touches C++.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HAL_SCREEN_W 320
#define HAL_SCREEN_H 240

// Speaker channel 0 carries music; SFX use 1..HAL_SFX_CHANNELS.
#define HAL_SFX_CHANNELS 7

typedef struct {
    bool btn_a, btn_b, btn_c;    // the three touch zones under the screen
    bool touching;               // a finger on the screen area itself (y < 240)
    int touch_x, touch_y;
    bool imu_ok;
    float ax, ay, az;            // accelerometer, in g
} hal_input_t;

void hal_init(void);

// Draws an 8-bit indexed frame through a byte-swapped RGB565 palette,
// centred vertically when h < 240.
void hal_display_frame(const uint8_t *fb, const uint16_t *palette_be, int w, int h);
void hal_display_text(const char *msg);

void hal_input_read(hal_input_t *in);

// Vibration motor strength, 0 = off. Applies immediately; timing is the
// caller's job.
void hal_vibrate(uint8_t level);

// Doom sound effects are unsigned 8-bit mono.
bool hal_sfx_play(int channel, const uint8_t *data, size_t len, uint32_t rate, uint8_t volume);
void hal_sfx_volume(int channel, uint8_t volume);
void hal_sfx_stop(int channel);
bool hal_sfx_playing(int channel);

// Interleaved stereo 16-bit; `frames` sample pairs. Queues behind what is
// already playing (the speaker holds two buffers per channel).
bool hal_music_play(const int16_t *stereo, size_t frames, uint32_t rate);
int hal_music_queued(void);

#ifdef __cplusplus
}
#endif
