# main/bot_key.txt (gitignored) holds the muninn-pager worker's device key.
# Without it the firmware builds with the Claude bot switched off.
set(embed "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bot_key.txt")
    set(embed "bot_key.txt")
endif()

idf_component_register(
    SRCS "main.cpp" "provision.c"
    INCLUDE_DIRS "."
    EMBED_TXTFILES ${embed}
    REQUIRES wa nvs_flash esp_wifi esp_netif esp_event esp_http_server esp_timer esp_rom mbedtls lwip esp_driver_uart json)

if(embed)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE HAVE_BOT_KEY=1)
endif()
