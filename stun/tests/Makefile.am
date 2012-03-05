#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk
AM_CPPFLAGS = -I$(top_srcdir)
AM_CFLAGS = -std=gnu99
LDADD = $(top_builddir)/stun/libstun.la

check_PROGRAMS = \
	test-parse \
	test-format \
	test-bind \
	test-conncheck \
	test-hmac

if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
  LDADD += -lws2_32
endif

dist_check_SCRIPTS = check-bind.sh

TESTS = $(check_PROGRAMS)
#$(dist_check_SCRIPTS)
