
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

