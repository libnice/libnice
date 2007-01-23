
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

COMMON_LDADD = libstun.la $(GLIB_LIBS)

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = stun.h stun.c

noinst_PROGRAMS = stun-client stun-server

stun_client_LDADD = $(COMMON_LDADD)

stun_server_LDADD = $(COMMON_LDADD)

check_PROGRAMS = test

TESTS = $(check_PROGRAMS)

test_LDADD = $(CHECK_LIBS) $(COMMON_LDADD)

