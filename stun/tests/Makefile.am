#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk
AM_CPPFLAGS = -I$(srcdir)/..

check_PROGRAMS = test-crc32 test-parse test-format test-bind
test_crc32_SOURCES = crc32.c
test_parse_SOURCES = parse.c
test_parse_LDADD = ../libstun.la
test_format_SOURCES = format.c
test_format_LDADD = ../libstun.la
test_bind_SOURCES = bind.c
test_bind_LDADD = ../libstun.la

dist_check_SCRIPTS = check-bind.sh

TESTS = test-crc32 test-parse test-format check-bind.sh
