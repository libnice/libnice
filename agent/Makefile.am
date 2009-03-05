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
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

COMMON_LDADD = libagent.la $(GLIB_LIBS)

dist_noinst_DATA = agent-signals-marshal.list
noinst_LTLIBRARIES = libagent.la

agent-signals-marshal.h: agent-signals-marshal.list
	glib-genmarshal --header --prefix=agent_marshal $< > $@

agent-signals-marshal.c: agent-signals-marshal.list Makefile.am
	glib-genmarshal --body --prefix=agent_marshal $< > $@
	sed -i "1i#include \"agent-signals-marshal.h\"" $@
	sed -i -e 's/^}$$/(void)return_value;(void)invocation_hint;}/' $@

BUILT_SOURCES = \
	agent-signals-marshal.h \
	agent-signals-marshal.c

CLEANFILES += $(BUILT_SOURCES)

libagent_la_SOURCES = \
	address.h \
	address.c \
	debug.h \
	debug.c \
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
	interfaces.c \
	interfaces.h \
	$(BUILT_SOURCES)

libagent_la_LIBADD = \
	$(top_builddir)/random/librandom.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la
libagent_la_DEPENDENCIES = \
	$(top_builddir)/random/librandom.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la

pkginclude_HEADERS = agent.h candidate.h debug.h address.h interfaces.h
