
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libstun_la_SOURCES = stun.h stun.c

noinst_LTLIBRARIES = libstun.la

noinst_PROGRAMS = stun-client stun-server test

stun_client_LDADD = libstun.la $(GLIB_LIBS)

stun_server_LDADD = libstun.la $(GLIB_LIBS)

test_LDADD = libstun.la $(GLIB_LIBS) $(CHECK_LIBS)

TESTS = test

