idf_component_register(SRC_DIRS "." INCLUDE_DIRS ".")

# Flags follow retro-go's prboom-go build. RETRO_GO is deliberately not
# defined: the engine then logs through vprintf and aborts on I_Error.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -DHAVE_CONFIG_H
    -O2
    -fjump-tables
    -ftree-switch-conversion
    -Wno-error
    -Wno-address
    -Wno-misleading-indentation
    -Wno-format-overflow
    -Wno-char-subscripts
    -Wno-missing-field-initializers
    -Wno-unused-variable
    -Wno-unused-but-set-variable
    -Wno-int-to-pointer-cast
    -Wno-pointer-to-int-cast
)
