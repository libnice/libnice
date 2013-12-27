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
	$(top_builddir)/agent/libagent.la \
	libnice.sym

libnice_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GUPNP_LIBS) \
	$(top_builddir)/agent/libagent.la

libnice_la_LDFLAGS = \
	-export-symbols $(srcdir)/libnice.sym \
	$(LIBNICE_LT_LDFLAGS)


AM_CFLAGS = \
	$(LIBNICE_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

test-symbols.sh::
	chmod +x $(srcdir)/$@

libnice-symbols-test.c: libnice.sym
	rm -f $@
	while read s; do echo "void $$s(void) { }" ; done < $? > $@

libnice-symbols-test.o: libnice-symbols-test.c
	$(CC) $(CFLAGS) -c -o $@ $?

libnice.symbols: libnice-symbols-test.o
	rm -f $@
	$(top_srcdir)/scripts/make-symbol-list.sh $? > $@

CLEANFILES += libnice.symbols libnice-symbols-test.c libnice-symbols-test.o

check_SCRIPTS = test-symbols.sh
check_DATA = libnice.symbols

TESTS = $(check_SCRIPTS)

EXTRA_DIST = $(check_SCRIPTS) libnice.sym libnice.ver

pkginclude_HEADERS = nice.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nice.pc

