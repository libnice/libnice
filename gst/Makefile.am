
AM_CFLAGS = -Wall -Werror \
	$(GST_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/address \
	-I $(top_srcdir)/stun

COMMON_LDADD = \
	$(GST_LIBS) \
	$(top_builddir)/nice/libnice.la

# libgstnice

lib_LTLIBRARIES = libgstnice.la

libgstnice_la_SOURCES = \
	gstnicesrc.h \
	gstnicesrc.c \
	gstnicesink.h \
	gstnicesink.c \
	gstnice.h \
	gstnice.c

libgstnice_la_LIBADD = $(COMMON_LDADD)

libgstnice_la_LDFLAGS = -module -avoid-version

# programs

check_PROGRAMS = \
	test

test_LDADD = \
	$(COMMON_LDADD) \
	../stun/libstun.la \
	libgstnice.la

TESTS = $(check_PROGRAMS)

noinst_PROGRAMS = \
	jingle-gst-test-server

jingle_gst_test_server_LDADD = libgstnice.la $(COMMON_LDADD)

