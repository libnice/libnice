
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

liblocal_a_SOURCES = local.c

noinst_LIBRARIES = liblocal.a

noinst_PROGRAMS = list-local-interfaces

list_local_interfaces_LDADD = $(GLIB_LIBS) liblocal.a

