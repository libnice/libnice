
include $(top_srcdir)/common.mk

AM_CFLAGS = \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/address \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun

COMMON_LDADD = libagent.la $(GLIB_LIBS)

noinst_LTLIBRARIES = libagent.la

libagent_la_SOURCES = \
	candidate.h \
	candidate.c \
	agent.h \
	agent.c

libagent_la_LIBADD = \
	$(top_builddir)/address/libaddress.la \
	$(top_builddir)/random/librandom.la \
	$(top_builddir)/udp/libudp.la \
	$(top_builddir)/stun/libstun.la

check_PROGRAMS = \
	test \
	test-add-remove-stream \
	test-recv \
	test-send \
	test-stun \
	test-priority \
	test-poll \
	test-mainloop

TESTS = $(check_PROGRAMS)

test_LDADD = $(COMMON_LDADD)

test_add_remove_stream_LDADD = $(COMMON_LDADD)

test_recv_LDADD = $(COMMON_LDADD)

test_send_LDADD = $(COMMON_LDADD)

test_stun_LDADD = $(COMMON_LDADD)

test_priority_LDADD = $(COMMON_LDADD)

test_poll_LDADD = $(COMMON_LDADD)

test_mainloop_LDADD = $(COMMON_LDADD)

pkginclude_HEADERS = agent.h candidate.h

