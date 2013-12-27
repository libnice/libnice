#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = $(LIBNICE_CFLAGS) $(GLIB_CFLAGS)

noinst_LTLIBRARIES = libnice-random.la

libnice_random_la_SOURCES = \
	random.h \
	random.c \
	random-glib.h \
	random-glib.c

check_PROGRAMS = test

test_LDADD = libnice-random.la $(GLIB_LIBS)

TESTS = $(check_PROGRAMS)

