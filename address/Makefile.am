#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = $(ERROR_CFLAGS) $(GLIB_CFLAGS)

# library

noinst_LTLIBRARIES = libaddress.la

libaddress_la_SOURCES = \
	address.h \
	address.c

pkginclude_HEADERS = address.h

# tests

check_PROGRAMS = test

test_LDADD = libaddress.la $(GLIB_LIBS)

TESTS = $(check_PROGRAMS)

