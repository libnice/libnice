
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

noinst_LTLIBRARIES = liblocal.la

liblocal_la_SOURCES = local.h local.c

noinst_PROGRAMS = list-local-interfaces

list_local_interfaces_LDADD = liblocal.la $(GLIB_LIBS)

