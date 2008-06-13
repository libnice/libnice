#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

SUBDIRS = . tools tests

include $(top_srcdir)/common.mk

AM_CFLAGS = -std=gnu99 $(ERROR_CFLAGS) $(OPENSSL_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = stun.h constants.h \
	stunagent.c stunagent.h \
	stunmessage.c stunmessage.h \
	stun3489bis.c stun3489bis.h \
	stuncrc32.c stuncrc32.h \
	stunhmac.c stunhmac.h \
	utils.c  utils.h
#	usages/stun-ice.c usages/stun-ice.h

libstun_la_LIBADD = $(OPENSSL_LIBS) $(LIBRT)

