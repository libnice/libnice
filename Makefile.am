#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include common.mk

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = \
	stun \
	socket \
	random \
	agent \
	nice \
	gst \
	docs \
	tests \
	examples

DISTCHECK_CONFIGURE_FLAGS = --disable-assert -enable-gtk-doc --enable-introspection

EXTRA_DIST = \
	COPYING.LGPL \
	COPYING.MPL \
	README.win32 \
	autogen.sh \
	common.mk \
	scripts/lcov.mk \
	scripts/lcov.sh \
	scripts/valgrind.sh \
	win32 \
	m4/introspection.m4

MAINTAINERCLEANFILES = ar-lib

dist_check_SCRIPTS = \
	scripts/check-symbols.sh \
	scripts/make-symbol-list.sh

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

clean-local:
	rm -rf doc

.PHONY: doc lcov-report lcov
