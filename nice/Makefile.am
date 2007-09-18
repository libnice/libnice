#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

lib_LTLIBRARIES = libnice.la

libnice_la_SOURCES =
libnice_la_DEPENDENCIES = \
	../local/liblocal.la \
	../agent/libagent.la \
	libnice.sym

libnice_la_LIBADD = \
	$(GLIB_LIBS) \
	../local/liblocal.la \
	../agent/libagent.la

libnice_la_LDFLAGS = \
	-export-symbols $(srcdir)/libnice.sym \
	-version-info 0:0:0

AM_CFLAGS = \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/address \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun

EXTRA_PROGRAMS = \
	ice-test-client \
	ice-test-server \
	jingle-test-server

COMMON_LDADD = libnice.la $(GLIB_LIBS)

ice_test_client_SOURCES = \
	ice-test-client.c \
	readline.h \
	readline.c \
	util.h \
	util.c

ice_test_client_LDADD = $(top_builddir)/stun/libstun.la $(COMMON_LDADD)

ice_test_server_SOURCES = \
	ice-test-server.c \
	readline.h \
	readline.c \
	util.h \
	util.c

ice_test_server_LDADD = $(COMMON_LDADD)

jingle_test_server_LDADD = $(COMMON_LDADD)

check_PROGRAMS = \
	test-readline

# XXX: test programs disabled due to changes in API
EXTRA_PROGRAMS += \
	test-util

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(COMMON_LDADD)

test_util_SOURCES = test-util.c util.h util.c

test_util_LDADD = $(COMMON_LDADD)

test-symbols.sh::
	chmod +x $(srcdir)/$@

libnice.symbols: libnice.sym Makefile
	rm -f $@
	while read s; do echo "T $$s"; done < $< > $@

CLEANFILES += libnice.symbols

check_SCRIPTS = test-symbols.sh
check_DATA = libnice.symbols

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

EXTRA_DIST = $(check_SCRIPTS) libnice.sym

pkginclude_HEADERS = nice.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nice.pc

