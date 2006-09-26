
AM_CFLAGS = -std=c99 -Wall -Werror

test_SOURCES = test.c $(top_srcdir)/stun/stun.h $(top_srcdir)/stun/stun.c
test_CFLAGS = -I$(top_srcdir)/stun $(AM_CFLAGS) @CHECK_CFLAGS@ @GLIB_CFLAGS@
test_LDADD = @CHECK_LIBS@ @GLIB_LIBS@

TESTS = test
noinst_PROGRAMS = test

