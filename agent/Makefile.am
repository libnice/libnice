
include $(top_srcdir)/common.mk

AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/address \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun \
	$(GLIB_CFLAGS)

COMMON_LDADD = libagent.la $(GLIB_LIBS)

noinst_LTLIBRARIES = libagent.la

libagent_la_SOURCES = \
	candidate.h \
	candidate.c \
	agent.h \
	agent.c \
	event.h \
	event.c

libagent_la_LIBADD = \
	$(top_builddir)/address/libaddress.la \
	$(top_builddir)/random/librandom.la \
	$(top_builddir)/udp/libudp.la \
	$(top_builddir)/stun/libstun.la

check_PROGRAMS = \
	test \
	test-add-stream \
	test-recv \
	test-stun \
	test-priority

TESTS = $(check_PROGRAMS)

test_LDADD = libagent.la $(GLIB_LIBS)

test_add_stream_LDADD = $(COMMON_LDADD)

test_recv_LDADD = $(COMMON_LDADD)

test_stun_LDADD = $(COMMON_LDADD)

test_priority_LDADD = $(COMMON_LDADD)

pkginclude_HEADERS = agent.h candidate.h event.h

