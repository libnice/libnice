
lib_LTLIBRARIES = libnice.la

libnice_la_SOURCES = libnice.ver

libnice_la_LIBADD = \
	$(top_builddir)/local/liblocal.la \
	$(top_builddir)/agent/libagent.la

libnice_la_LDFLAGS = -Wl,--version-script,$(srcdir)/libnice.ver

noinst_PROGRAMS = ice-test-client ice-test-server

AM_CFLAGS = -Wall -Werror \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/stun \
	$(GLIB_CFLAGS)

COMMON_LDADD = $(top_builddir)/agent/libagent.la $(GLIB_LIBS)

ice_test_client_SOURCES = \
	ice-test-client.c \
	readline.h \
	readline.c \
	util.h \
	util.c

ice_test_client_LDADD = $(COMMON_LDADD)

ice_test_server_SOURCES = \
	ice-test-server.c \
	readline.h \
	readline.c \
	util.h \
	util.c

ice_test_server_LDADD = $(COMMON_LDADD)

check_PROGRAMS = \
	test-readline \
	test-util

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(COMMON_LDADD)

test_util_SOURCES = test-util.c util.h util.c

test_util_LDADD = $(COMMON_LDADD)

TESTS = test-readline test-util

pkginclude_HEADERS = nice.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnice.pc

