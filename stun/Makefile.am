
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = stun.h stun.c

noinst_PROGRAMS = stun-client stun-server

stun_client_LDADD = libstun.la $(GLIB_LIBS)

stun_server_LDADD = libstun.la $(GLIB_LIBS)

check_PROGRAMS = test

test_LDADD = libstun.la $(GLIB_LIBS) $(CHECK_LIBS)

TESTS = test

