# Host build of the wa core, for testing against WhatsApp's servers before
# flashing. MBEDTLS points at an mbedTLS 3.6 checkout built with `make lib`
# (ESP-IDF 5.4 ships mbedTLS 3.6, so both builds use the same API).
MBEDTLS ?= /tmp/jail/mbedtls
WA = ../components/wa
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS += -I$(WA) -I$(WA)/include -I$(MBEDTLS)/include
SRCS = main.c $(WA)/wa_client.c $(WA)/wa_message.c $(WA)/wa_signal.c $(WA)/wa_binary.c $(WA)/wa_tokens.c $(WA)/wa_pb.c $(WA)/wa_crypto.c \
       $(WA)/third_party/monocypher.c $(WA)/third_party/monocypher-ed25519.c
LIBS = $(MBEDTLS)/library/libmbedcrypto.a -lz

all: wa-host test-wa

wa-host: $(SRCS) $(wildcard $(WA)/*.h) $(WA)/include/wa.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LIBS)

TEST_SRCS = test_wa.c $(WA)/wa_client.c $(WA)/wa_message.c $(WA)/wa_signal.c $(WA)/wa_binary.c $(WA)/wa_tokens.c $(WA)/wa_pb.c $(WA)/wa_crypto.c \
            $(WA)/third_party/monocypher.c $(WA)/third_party/monocypher-ed25519.c

test-wa: $(TEST_SRCS) $(wildcard $(WA)/*.h)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRCS) $(LIBS)

test: test-wa
	./test-wa

clean:
	rm -f wa-host test-wa

.PHONY: all clean test
