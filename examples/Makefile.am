#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = \
	-I $(top_srcdir) \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
        $(GUPNP_CFLAGS)

bin_PROGRAMS = simple-example

simple_example_SOURCES = simple-example.c
simple_example_LDADD = $(top_builddir)/agent/libagent.la \
	 $(top_builddir)/socket/libsocket.la \
	 $(GLIB_LIBS) $(GUPNP_LIBS)
