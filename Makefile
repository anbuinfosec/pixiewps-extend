CFLAGS = -O3

PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/share/man

SRCDIR = src
HDRS = $(SRCDIR)/config.h $(SRCDIR)/endianness.h $(SRCDIR)/version.h
HDRS += $(SRCDIR)/pixiewps.h $(SRCDIR)/utils.h $(SRCDIR)/wps.h

# Extended framework headers
HDRS += $(SRCDIR)/pixiewps_extended.h $(SRCDIR)/wifi_scanner.h
HDRS += $(SRCDIR)/client_recon.h $(SRCDIR)/monitor_mode.h
HDRS += $(SRCDIR)/adapter_intel.h $(SRCDIR)/packet_injection.h
HDRS += $(SRCDIR)/wps_engine.h $(SRCDIR)/pmkid_capture.h
HDRS += $(SRCDIR)/handshake_capture.h $(SRCDIR)/wpa3_handler.h
HDRS += $(SRCDIR)/target_priority.h $(SRCDIR)/router_prng.h
HDRS += $(SRCDIR)/wps_protocol.h

# Internal flags so one can safely override CFLAGS, CPPFLAGS and LDFLAGS
INTFLAGS = -std=c99 -I $(SRCDIR)/crypto/tc
LIBS = -lpthread -lm

ifeq ($(OPENSSL),1)
LIBS += -lcrypto
INTFLAGS += -DUSE_OPENSSL
endif

TARGET = pixiewps

include $(SRCDIR)/crypto/tfm/sources.mak
TFMSRC = $(patsubst ./%,$(SRCDIR)/crypto/tfm/%,$(TFM_SRCS))
TFMOBJS = $(TFMSRC:.c=.o)
TC_SRCS = ./aes_cbc.c ./aes.c
TCSRC = $(patsubst ./%,$(SRCDIR)/crypto/tc/%,$(TC_SRCS))
TCOBJS = $(TCSRC:.c=.o)

# Extended framework sources
FRAMEWORK_SOURCES = $(SRCDIR)/pixiewps_modules.c $(SRCDIR)/wifi_scanner.c \
                   $(SRCDIR)/router_prng.c $(SRCDIR)/wps_protocol.c

SOURCE = $(SRCDIR)/pixiewps.c

-include config.mak

.PHONY: all install install-bin install-man strip clean

all: $(TARGET) pixiewrapper

pixiewrapper: $(SRCDIR)/pixiewrapper.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(TARGET): $(SOURCE) $(HDRS) $(FRAMEWORK_SOURCES) $(TFMOBJS) $(TCOBJS)
	$(CC) $(INTFLAGS) $(CFLAGS) $(CPPFLAGS) -o $(TARGET) $(SOURCE) $(FRAMEWORK_SOURCES) $(LIBS) $(LDFLAGS) $(TFMOBJS) $(TCOBJS)

$(SRCDIR)/crypto/tfm/%.o: $(SRCDIR)/crypto/tfm/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -I$(SRCDIR)/crypto/tfm -c -o $@ $<

$(SRCDIR)/crypto/tc/%.o: $(SRCDIR)/crypto/tc/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -I$(SRCDIR)/crypto/tc -c -o $@ $<

install: install-bin install-man

install-bin: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $< $(DESTDIR)$(BINDIR)

install-man: pixiewps.1
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 $< $(DESTDIR)$(MANDIR)/man1

strip: $(TARGET)
	strip $(TARGET)

clean:
	rm -f $(TARGET) $(TFMOBJS) $(TCOBJS)
