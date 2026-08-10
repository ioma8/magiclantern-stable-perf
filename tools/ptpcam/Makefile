CC=gcc
# The protocol code packs pointers into 32-bit fields, so build 32-bit where
# the platform supports it (Linux x86_64 with multilib).  On other platforms
# (e.g. arm64 macOS) -m32 is unavailable, so build 64-bit and accept that
# pointer-sized fields are truncated.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
LDFLAGS=-lusb
# The protocol code packs pointers into 32-bit fields, so build 32-bit where
# the platform supports it (Linux x86_64 with multilib).  On other platforms
# -m32 is unavailable; ptp.c refuses 64-bit builds unless PTP_ALLOW_64BIT is
# defined (camera-side addresses packed into protocol fields are 32-bit, so
# this is believed safe).
ifneq ($(filter Linux%,$(UNAME_S)),)
ifneq ($(filter x86_64%,$(UNAME_M)),)
CFLAGS=-m32
else
CFLAGS=-DPTP_ALLOW_64BIT
endif
else
CFLAGS=-DPTP_ALLOW_64BIT
endif
# Homebrew on macOS installs usb.h/libusb outside the default search paths
ifeq ($(UNAME_S),Darwin)
CFLAGS += -I/opt/homebrew/include
LDFLAGS += -L/opt/homebrew/lib
endif

all: ptpcam

clean:
	-rm ptpcam

ptpcam: config.h libptp-endian.h libptp-stdint.h myusb.c properties.c ptp-pack.c ptp.c ptp.h ptpcam.c ptpcam.h
	$(CC) -o ptpcam myusb.c properties.c ptp.c ptpcam.c $(CFLAGS) $(LDFLAGS)
