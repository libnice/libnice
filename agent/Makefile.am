
AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libagent.la

libagent_la_SOURCES = \
	address.h \
	address.c \
	agent.h \
	agent.c

libagent_la_LIBADD = \
	$(top_builddir)/udp/libudp.la \
	$(top_builddir)/stun/libstun.la

check_PROGRAMS = \
	test \
	test-readline \
	test-util \
	test-add-stream \
	test-recv \
	test-stun

test_LDADD = libagent.la $(GLIB_LIBS)

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(GLIB_LIBS)

test_util_SOURCES = test-util.c util.h util.c

test_util_LDADD = libagent.la $(GLIB_LIBS)

test_add_stream_LDADD = libagent.la $(GLIB_LIBS)

test_recv_LDADD = libagent.la $(GLIB_LIBS)

test_stun_LDADD = libagent.la $(GLIB_LIBS)

TESTS = $(check_PROGRAMS)

pkginclude_HEADERS = agent.h

