idf_component_register(
    SRCS "doom_main.c" "m5_hal.cpp"
    INCLUDE_DIRS "."
    REQUIRES prboom fatfs esp_timer esp_partition
)

# Packs ../wads into a FAT image and flashes it to the `wads` partition with
# `idf.py flash`. Mounted read-only at /wads.
fatfs_create_rawflash_image(wads ../wads FLASH_IN_PROJECT)
