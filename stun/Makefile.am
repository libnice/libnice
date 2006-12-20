
AM_CFLAGS = -Wall $(GLIB_CFLAGS)

libstun_a_SOURCES = stun.c

noinst_LIBRARIES = libstun.a

noinst_PROGRAMS = stun-client

stun_client_LDADD = libstun.a $(GLIB_LIBS)

