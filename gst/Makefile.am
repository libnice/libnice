#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

AM_CFLAGS = $(LIBNICE_CFLAGS) \
	$(GST_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/stun

COMMON_LDADD = \
	$(GST_LIBS) \
	$(top_builddir)/nice/libnice.la

# libgstnice

gstplugin_LTLIBRARIES = libgstnice.la

libgstnice_la_SOURCES = \
	gstnicesrc.h \
	gstnicesrc.c \
	gstnicesink.h \
	gstnicesink.c \
	gstnice.h \
	gstnice.c

libgstnice_la_LIBADD = $(COMMON_LDADD)

libgstnice_la_LDFLAGS = -module -avoid-version
