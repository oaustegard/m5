idf_component_register(
    SRCS "main.cpp" "provision.c"
    INCLUDE_DIRS "."
    REQUIRES wa nvs_flash esp_wifi esp_netif esp_event esp_http_server esp_timer esp_rom mbedtls lwip esp_driver_uart)
