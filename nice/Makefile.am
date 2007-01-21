
lib_LTLIBRARIES = libnice.la

libnice_la_SOURCES =

EXTRA_libnice_la_SOURCES = libnice.ver

libnice_la_LIBADD = \
	../local/liblocal.la \
	../udp/libudp.la \
	../stun/libstun.la \
	../agent/libagent.la

libnice_la_LDFLAGS = -Wl,--version-script,$(srcdir)/libnice.ver

