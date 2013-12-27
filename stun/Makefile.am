#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

SUBDIRS = . tools tests

include $(top_srcdir)/common.mk

AM_CFLAGS = -std=gnu99 -DG_LOG_DOMAIN=\"libnice-stun\" $(LIBNICE_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)

if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
endif

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = constants.h \
	stunagent.c stunagent.h \
	stunmessage.c stunmessage.h \
	stun5389.c stun5389.h \
	stuncrc32.c stuncrc32.h \
	sha1.c sha1.h \
	md5.c md5.h \
	rand.c rand.h \
	stunhmac.c stunhmac.h \
	utils.c  utils.h \
	debug.c  debug.h \
	usages/ice.c usages/ice.h \
	usages/bind.c usages/bind.h \
	usages/turn.c usages/turn.h \
	usages/timer.c usages/timer.h

libstun_la_LIBADD = $(LIBRT)

EXTRA_DIST = win32_common.h

libstun_la_includedir=$(includedir)/stun
libstun_la_include_HEADERS = stunagent.h stunmessage.h win32_common.h debug.h constants.h

libstun_usage_includedir=$(includedir)/stun/usages
libstun_usage_include_HEADERS = usages/bind.h usages/ice.h usages/turn.h usages/timer.h
