#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

AM_CFLAGS = $(LIBNICE_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/stun

COMMON_LIBADD = \
	$(top_builddir)/nice/libnice.la

# libgstnice

if WITH_GSTREAMER
gstplugin_LTLIBRARIES = libgstnice.la

libgstnice_la_CFLAGS = $(AM_CFLAGS) $(GST_CFLAGS) -DGST_USE_UNSTABLE_API

libgstnice_la_SOURCES = \
	gstnicesrc.h \
	gstnicesrc.c \
	gstnicesink.h \
	gstnicesink.c \
	gstnice.h \
	gstnice.c

libgstnice_la_LIBADD = 	$(COMMON_LIBADD) $(GST_LIBS)

libgstnice_la_LDFLAGS = -module -avoid-version -no-undefined
endif


if WITH_GSTREAMER010
gstplugin010_LTLIBRARIES = libgstnice010.la

libgstnice010_la_CFLAGS = $(AM_CFLAGS) $(GST010_CFLAGS)

libgstnice010_la_SOURCES = \
	gstnicesrc.h \
	gstnicesrc.c \
	gstnicesink.h \
	gstnicesink.c \
	gstnice.h \
	gstnice.c

libgstnice010_la_LIBADD = $(COMMON_LIBADD) $(GST010_LIBS)

libgstnice010_la_LDFLAGS = -module -avoid-version -no-undefined
endif
