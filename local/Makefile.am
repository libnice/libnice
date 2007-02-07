
include $(top_srcdir)/common.mk

AM_CFLAGS = \
	-Wall -Werror \
	$(GLIB_CFLAGS) \
	-I $(top_srcdir)/address

noinst_LTLIBRARIES = liblocal.la

liblocal_la_SOURCES = local.h local.c

noinst_PROGRAMS = list-local-interfaces

list_local_interfaces_LDADD = \
	$(GLIB_LIBS) \
	liblocal.la \
	$(top_builddir)/address/libaddress.la

