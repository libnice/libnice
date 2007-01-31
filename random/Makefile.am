
AM_CFLAGS = -Wall -Werror $(GLIB_CFLAGS)

noinst_LTLIBRARIES = librandom.la

librandom_la_SOURCES = \
	random.h \
	random.c \
	random-glib.h \
	random-glib.c

check_PROGRAMS = test

test_LDADD = $(GLIB_LIBS) librandom.la

TESTS = $(check_PROGRAMS)

pkginclude_HEADERS = random.h

