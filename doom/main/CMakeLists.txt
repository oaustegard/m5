# CONFIG_DOOM_QEMU swaps the M5Unified HAL for one that draws to Espressif
# QEMU's virtual RGB panel and plays back a scripted input sequence.
if(CONFIG_DOOM_QEMU)
    set(hal_src "qemu_hal.c")
else()
    set(hal_src "m5_hal.cpp")
endif()

idf_component_register(
    SRCS "doom_main.c" ${hal_src}
    INCLUDE_DIRS "."
    REQUIRES prboom fatfs esp_timer esp_partition
)

# Packs ../wads into a FAT image and flashes it to the `wads` partition with
# `idf.py flash`. Mounted read-only at /wads.
fatfs_create_rawflash_image(wads ../wads FLASH_IN_PROJECT)
