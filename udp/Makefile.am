
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

COMMON_LDADD = libudp.la $(GLIB_LIBS)

noinst_LTLIBRARIES = libudp.la

libudp_la_SOURCES = \
	udp.h \
	udp-generic.c \
	udp-bsd.h \
	udp-bsd.c \
	udp-fake.h \
	udp-fake.c

noinst_PROGRAMS = udp-client udp-echo-server

udp_client_LDADD = $(COMMON_LDADD)

udp_echo_server_LDADD = $(COMMON_LDADD)

check_PROGRAMS = test

test_LDADD = $(COMMON_LDADD)

test-echo.sh::
	chmod +x $(srcdir)/$@

EXTRA_DIST = test-echo.sh

TESTS = test-echo.sh test

pkginclude_HEADERS = udp.h udp-fake.h

