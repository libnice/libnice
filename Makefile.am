#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include common.mk

SUBDIRS = \
	address \
	local \
	stun \
	tests \
	udp \
	random \
	agent \
	nice

if WITH_GSTREAMER
	SUBDIRS += gst
endif

DIST_SUBDIRS = $(SUBDIRS) gst

EXTRA_DIST = scripts common.mk

lcov:
	find -name '*.gcda' -delete
	$(MAKE) $(AM_MAKEFLAGS) check
	find -type d -name '.libs' | while read d ; do \
		mv -fv $$d/*.gc* $$d/.. 2>/dev/null || true ; \
	done
	$(MAKE) lcov-report

lcov-report:
	mkdir -p lcov
	lcov -d . -c > lcov/lcov.info
	lcov -l lcov/lcov.info 2>/dev/null | \
	  egrep '(^/usr|/test.*\.c)' | \
	  cut -d: -f1 > lcov/lcov.remove
	lcov -r lcov/lcov.info `cat lcov/lcov.remove` 2>/dev/null > lcov/lcov.info.clean
	genhtml -o lcov lcov/lcov.info.clean

.PHONY: lcov-report lcov
