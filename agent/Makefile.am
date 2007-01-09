
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libagent_a_SOURCES = agent.h agent.c

noinst_LIBRARIES = libagent.a

noinst_PROGRAMS = test

test_LDADD = libagent.a $(GLIB_LIBS)

TESTS = test

