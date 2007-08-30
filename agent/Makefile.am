#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

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

%-signals-marshal.h: %-signals-marshal.list
	glib-genmarshal --header --prefix=$(subst -,_,$*)_marshal $< > $@

%-signals-marshal.c: %-signals-marshal.list Makefile.am
	glib-genmarshal --body --prefix=$(subst -,_,$*)_marshal $< > $@
	sed -i "1i#include \"$*-signals-marshal.h\"" $@
	sed -i -e 's/^}$$/(void)return_value;(void)invocation_hint;}/' $@

BUILT_SOURCES = \
	agent-signals-marshal.h \
	agent-signals-marshal.c

CLEANFILES += $(BUILT_SOURCES)

libagent_la_SOURCES = \
	candidate.h \
	candidate.c \
	component.h \
	component.c \
	agent.h \
	agent-priv.h \
	agent.c \
	stream.h \
	stream.c \
	conncheck.c \
	conncheck.h \
	discovery.c \
	discovery.h \
	$(BUILT_SOURCES)

libagent_la_LIBADD = \
	$(top_builddir)/address/libaddress.la \
	$(top_builddir)/random/librandom.la \
	$(top_builddir)/udp/libudp.la \
	$(top_builddir)/stun/libstun.la

check_PROGRAMS = \
	test \
	test-add-remove-stream \
	test-recv \
	test-priority \
	test-poll \
	test-mainloop \
	test-fullmode \
	test-restart \
	test-fallback

check_SCRIPTS = \
	check-test-fullmode-with-stun.sh

# disabled test programs (using the old STUN API):
EXTRA_PROGRAMS = \
	test-stun \
	test-send

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

test_LDADD = $(COMMON_LDADD)

test_add_remove_stream_LDADD = $(COMMON_LDADD)

test_recv_LDADD = $(COMMON_LDADD)

test_send_LDADD = $(COMMON_LDADD)

test_stun_LDADD = $(COMMON_LDADD)

test_priority_LDADD = $(COMMON_LDADD)

test_poll_LDADD = $(COMMON_LDADD)

test_mainloop_LDADD = $(COMMON_LDADD)

test_fullmode_LDADD = $(COMMON_LDADD)

test_restart_LDADD = $(COMMON_LDADD)

pkginclude_HEADERS = agent.h candidate.h

