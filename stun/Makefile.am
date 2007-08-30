#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

SUBDIRS = . tests

include $(top_srcdir)/common.mk

AM_CFLAGS = -std=gnu99 $(ERROR_CFLAGS) $(OPENSSL_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)

BUILT_SOURCES = unknown.c
CLEANFILES += $(BUILT_SOURCES)

noinst_LTLIBRARIES = libstun.la
dist_noinst_SCRIPTS = build-unknown.sh

libstun_la_SOURCES = \
	stun-msg.h stunsend.c stunrecv.c \
	unknown.c \
	crc32.c hmac.c \
	timer.h timer.c trans.h trans.c \
	bind.h stun-ice.h bind.c bindserv.c
#	relay.h relay.c
libstun_la_LIBADD = $(LIBS) $(OPENSSL_LIBS) $(LIBRT)

bin_PROGRAMS = stund stunbdc
check_PROGRAMS = stund

stund_LDADD = libstun.la -lpthread
stunbdc_LDADD = libstun.la

unknown.c: stun-msg.h build-unknown.sh
	rm -f unknown.c
	$(SHELL) "$(srcdir)/build-unknown.sh" < "$(srcdir)/stun-msg.h" > unknown.c

