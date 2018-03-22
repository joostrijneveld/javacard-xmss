CC = /usr/bin/gcc
CFLAGS = -Wall -O3 -Wextra -Wpedantic -I/usr/include/PCSC
LDLIBS = -lcrypto -lpcsclite

XMSS = xmss-reference

SOURCES = $(XMSS)/params.c $(XMSS)/hash.c $(XMSS)/fips202.c $(XMSS)/hash_address.c $(XMSS)/randombytes.c $(XMSS)/wots.c $(XMSS)/xmss.c $(XMSS)/xmss_core.c $(XMSS)/xmss_commons.c $(XMSS)/utils.c
HEADERS = $(XMSS)/params.h $(XMSS)/hash.h $(XMSS)/fips202.h $(XMSS)/hash_address.h $(XMSS)/randombytes.h $(XMSS)/wots.h $(XMSS)/xmss.h $(XMSS)/xmss_core.h $(XMSS)/xmss_commons.h $(XMSS)/utils.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

all: test

test: $(TESTS:=.exec)

.PHONY: clean test

test/%.exec: test/%
	@$<

test: test.c smartcard-xmss.c smartcard-xmss.h prepstate.c prepstate.h $(SOURCES_FAST) $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ smartcard-xmss.c prepstate.c $(SOURCES_FAST) $< $(LDLIBS)

clean:
	-$(RM) test
