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

BUILT_SOURCES = unknown.c
CLEANFILES += $(BUILT_SOURCES)

noinst_LTLIBRARIES = libstun.la
dist_noinst_SCRIPTS = build-unknown.sh

libstun_la_SOURCES = \
	stun-msg.h stunsend.c stunrecv.c \
	stun3489bis.c \
	utils.c \
	unknown.c \
	crc32.c hmac.c \
	timer.h timer.c trans.h trans.c \
	usages/stun-ice.c usages/stun-ice.h \
	usages/bind.c usages/bind.h

libstun_la_LIBADD = $(OPENSSL_LIBS) $(LIBRT)

unknown.c: stun-msg.h build-unknown.sh
	rm -f unknown.c
	$(SHELL) "$(srcdir)/build-unknown.sh" < "$(srcdir)/stun-msg.h" > unknown.c

