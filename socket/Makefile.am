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
	-I $(top_srcdir)/address \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/agent

COMMON_LDADD = libsocket.la $(GLIB_LIBS) $(top_builddir)/address/libaddress.la  $(top_builddir)/stun/libstun.la

noinst_LTLIBRARIES = libsocket.la

libsocket_la_SOURCES = \
	socket.h \
	socket.c \
	udp-bsd.h \
	udp-bsd.c \
	udp-turn.h \
	udp-turn.c \
	tcp-turn.h \
	tcp-turn.c

check_PROGRAMS = test-bsd

test_bsd_LDADD = $(COMMON_LDADD)


TESTS = $(check_PROGRAMS)

pkginclude_HEADERS = socket.h udp-bsd.h udp-turn.h tcp-turn.h

