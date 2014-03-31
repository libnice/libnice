#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = \
	-DG_LOG_DOMAIN=\"libnice\" \
	$(LIBNICE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUPNP_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
endif

noinst_LTLIBRARIES = libagent.la

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
	pseudotcp.h \
	pseudotcp.c \
	iostream.h \
	iostream.c \
	inputstream.h \
	inputstream.c \
	outputstream.h \
	outputstream.c \
	$(BUILT_SOURCES)

libagent_la_LIBADD = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la
libagent_la_DEPENDENCIES = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la

pkginclude_HEADERS = \
	agent.h \
	candidate.h \
	debug.h \
	address.h \
	interfaces.h \
	pseudotcp.h \
	$(NULL)

if WINDOWS
  libagent_la_LIBADD += -liphlpapi -lws2_32
endif
