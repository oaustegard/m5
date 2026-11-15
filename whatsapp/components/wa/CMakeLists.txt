idf_component_register(
    SRCS "wa_client.c" "wa_binary.c" "wa_tokens.c" "wa_pb.c" "wa_crypto.c"
         "third_party/monocypher.c" "third_party/monocypher-ed25519.c"
         "wa_platform_esp.c"
    INCLUDE_DIRS "include" "."
    REQUIRES mbedtls esp_rom esp_hw_support)
