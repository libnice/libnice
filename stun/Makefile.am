
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libstun_a_SOURCES = stun.h stun.c

noinst_LIBRARIES = libstun.a

noinst_PROGRAMS = stun-client stun-server test

stun_client_LDADD = libstun.a $(GLIB_LIBS)

stun_server_LDADD = libstun.a $(GLIB_LIBS)

test_LDADD = libstun.a $(GLIB_LIBS) $(CHECK_LIBS)

TESTS = test

