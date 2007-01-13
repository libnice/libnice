
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libudp_a_SOURCES = udp.h udp.c udp-generic.c udp-fake.h udp-fake.c

noinst_LIBRARIES = libudp.a

noinst_PROGRAMS = udp-client udp-echo-server

udp_client_LDADD = libudp.a $(GLIB_LIBS)

udp_echo_server_LDADD = libudp.a $(GLIB_LIBS)

check_PROGRAMS = test

test_LDADD = libudp.a $(GLIB_LIBS)

test-echo.sh::
	chmod +x $(srcdir)/$@

EXTRA_DIST = test-echo.sh

TESTS = test-echo.sh test

