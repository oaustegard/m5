// SPDX-License-Identifier: MIT
#include "m5_hal.h"

#include <M5Unified.h>
#include <esp_heap_caps.h>

// The frame goes out in horizontal bands through two DMA buffers: one is
// converted from palette indices while the other is on the SPI bus.
// pushImageDMA waits for the previous transfer before starting the next,
// so a buffer is free again by the time the loop comes back to it.
#define BAND_LINES 20

static uint16_t *band[2];

extern "C" void hal_init(void)
{
    auto cfg = M5.config();
    cfg.internal_imu = true;
    cfg.internal_spk = true;
    cfg.internal_mic = false;   // shares the I2S peripheral with the speaker
    M5.begin(cfg);

    M5.Display.setRotation(1);
    M5.Display.fillScreen(TFT_BLACK);

    auto spk = M5.Speaker.config();
    spk.task_pinned_core = 1;   // Doom's game loop runs on core 0
    spk.dma_buf_count = 8;
    spk.dma_buf_len = 256;
    M5.Speaker.config(spk);
    M5.Speaker.begin();
    M5.Speaker.setVolume(160);

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
