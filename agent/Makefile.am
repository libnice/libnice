
AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun \
	$(GLIB_CFLAGS)

COMMON_LDADD = libagent.la $(GLIB_LIBS)

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

TESTS = $(check_PROGRAMS)

test_LDADD = libagent.la $(GLIB_LIBS)

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(GLIB_LIBS)

test_util_SOURCES = test-util.c util.h util.c

test_util_LDADD = $(COMMON_LDADD)

test_add_stream_LDADD = $(COMMON_LDADD)

test_recv_LDADD = $(COMMON_LDADD)

test_stun_LDADD = $(COMMON_LDADD)

pkginclude_HEADERS = agent.h

