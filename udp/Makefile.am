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
	-I $(top_srcdir)/address

COMMON_LDADD = libudp.la $(GLIB_LIBS) $(top_builddir)/address/libaddress.la

noinst_LTLIBRARIES = libudp.la

libudp_la_SOURCES = \
	udp.h \
	udp-generic.c \
	udp-bsd.h \
	udp-bsd.c \
	udp-fake.h \
	udp-fake.c

noinst_PROGRAMS = udp-client udp-echo-server

udp_client_LDADD = $(COMMON_LDADD)

udp_echo_server_LDADD = $(COMMON_LDADD)

check_PROGRAMS = test-fake test-bsd
dist_check_SCRIPTS = test-echo.sh

test_fake_LDADD = $(COMMON_LDADD)

test_bsd_LDADD = $(COMMON_LDADD)

test-echo.sh::
	chmod +x $(srcdir)/$@

TESTS = $(dist_check_SCRIPTS) $(check_PROGRAMS)

pkginclude_HEADERS = udp.h udp-fake.h udp-bsd.h

