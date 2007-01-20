
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

liblocal_la_SOURCES = local.h local.c

noinst_LTLIBRARIES = liblocal.la

noinst_PROGRAMS = list-local-interfaces

list_local_interfaces_LDADD = $(GLIB_LIBS) liblocal.la

