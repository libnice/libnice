
AM_CFLAGS = -Wall -Werror \
	$(GST_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/udp \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/address

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

