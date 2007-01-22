
lib_LTLIBRARIES = libnice.la

libnice_la_SOURCES =

EXTRA_libnice_la_SOURCES = libnice.ver

libnice_la_LIBADD = \
	../local/liblocal.la \
	../agent/libagent.la

libnice_la_LDFLAGS = -Wl,--version-script,$(srcdir)/libnice.ver

noinst_PROGRAMS = ice-test-server

AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun \
	$(GLIB_CFLAGS)

ice_test_server_SOURCES = ice-test-server.c \
	$(top_srcdir)/agent/readline.h \
	$(top_srcdir)/agent/readline.c \
	$(top_srcdir)/agent/util.h \
	$(top_srcdir)/agent/util.c

ice_test_server_LDADD = \
	$(top_builddir)/agent/libagent.la \
	$(GLIB_LIBS)

