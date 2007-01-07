
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libstun_a_SOURCES = stun.c

noinst_LIBRARIES = libstun.a

noinst_PROGRAMS = stun-client stun-server

stun_client_LDADD = libstun.a $(GLIB_LIBS)

stun_server_LDADD = libstun.a $(GLIB_LIBS)

