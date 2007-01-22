
AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/udp \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libagent.la

libagent_la_SOURCES = agent.h agent.c

libagent_la_LIBADD = \
	$(top_builddir)/udp/libudp.la \
	$(top_builddir)/stun/libstun.la

check_PROGRAMS = test test-readline test-util test-add-stream test-recv

test_LDADD = libagent.la $(GLIB_LIBS)

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(GLIB_LIBS)

test_util_SOURCES = test-util.c util.h util.c

test_util_LDADD = libagent.la $(GLIB_LIBS)

test_add_stream_LDADD = libagent.la $(GLIB_LIBS)

test_recv_LDADD = libagent.la $(GLIB_LIBS)

TESTS = test test-readline test-util test-add-stream test-recv

