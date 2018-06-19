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
	tests \
	docs \
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
	scripts/valgrind-test-driver \
	win32 \
	win32/vs9/libnice.def \
	m4/introspection.m4

MAINTAINERCLEANFILES = ar-lib

dist_check_SCRIPTS = \
	scripts/check-symbols.sh \
	scripts/make-symbol-list.sh

# Generate the win32 DLL symbol export file.
# The stun_*() symbols at the end have historically been exported on Windows
# but not Linux, for no particular reason. They can’t be removed without
# breaking ABI. FIXME: Remove them when we next break ABI.
win32/vs9/libnice.def: nice/libnice.sym
	$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)(echo "LIBRARY libnice"; \
	            echo ""; \
	            echo "EXPORTS"; \
	            echo ""; \
	            cat $<; \
	            echo "stun_debug"; \
	            echo "stun_debug_bytes"; \
	            echo "stun_hash_creds") > $@

CLEANFILES += win32/vs9/libnice.def

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
