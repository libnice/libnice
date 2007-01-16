
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

libagent_a_SOURCES = agent.h agent.c

noinst_LIBRARIES = libagent.a

noinst_PROGRAMS = test test-readline

test_LDADD = libagent.a $(GLIB_LIBS)

test_readline_SOURCES = test-readline.c readline.h readline.c

test_readline_LDADD = $(GLIB_LIBS)

TESTS = test test-readline

