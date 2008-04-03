#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

AM_CFLAGS = -Wall -Werror \
	$(GST_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/address \
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

# programs

check_PROGRAMS = \
	test

test_LDADD = \
	$(COMMON_LDADD) \
	../stun/libstun.la \
	libgstnice.la

TESTS = $(check_PROGRAMS)

noinst_PROGRAMS = \
	jingle-gst-test-server

jingle_gst_test_server_LDADD = libgstnice.la $(COMMON_LDADD)

