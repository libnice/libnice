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
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/

COMMON_LDADD = libsocket.la $(top_builddir)/agent/libagent.la $(GLIB_LIBS) $(top_builddir)/stun/libstun.la

noinst_LTLIBRARIES = libsocket.la

libsocket_la_SOURCES = \
	socket.h \
	socket.c \
	udp-bsd.h \
	udp-bsd.c \
	tcp-bsd.h \
	tcp-bsd.c \
	pseudossl.h \
	pseudossl.c \
	socks5.h \
	socks5.c \
	turn.h \
	turn.c \
	tcp-turn.h \
	tcp-turn.c

check_PROGRAMS = test-bsd

test_bsd_LDADD = $(COMMON_LDADD)


TESTS = $(check_PROGRAMS)

pkginclude_HEADERS = socket.h udp-bsd.h tcp-bsd.h pseudossl.h turn.h tcp-turn.h socks5.h

