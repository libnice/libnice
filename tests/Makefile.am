#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
        $(GUPNP_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

COMMON_LDADD = $(top_builddir)/agent/libagent.la $(top_builddir)/socket/libsocket.la $(GLIB_LIBS) $(GUPNP_LIBS)

check_PROGRAMS = \
	test-pseudotcp \
	test-bsd \
	test \
	test-address \
	test-add-remove-stream \
	test-priority \
	test-mainloop \
	test-fullmode \
	test-restart \
	test-fallback \
	test-thread \
	test-dribble \
        test-new-dribble

dist_check_SCRIPTS = \
	check-test-fullmode-with-stun.sh \
	test-pseudotcp-random.sh

TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)

test_pseudotcp_LDADD = $(COMMON_LDADD)

test_bsd_LDADD = $(COMMON_LDADD)

test_LDADD = $(COMMON_LDADD)

test_thread_LDADD = $(COMMON_LDADD)

test_address_LDADD = $(COMMON_LDADD)

test_add_remove_stream_LDADD = $(COMMON_LDADD)

test_priority_LDADD = $(COMMON_LDADD)

test_mainloop_LDADD = $(COMMON_LDADD)

test_fullmode_LDADD = $(COMMON_LDADD)

test_restart_LDADD = $(COMMON_LDADD)

test_fallback_LDADD = $(COMMON_LDADD)

test_dribble_LDADD = $(COMMON_LDADD)

test_new_dribble_LDADD = $(COMMON_LDADD)

all-local:
	chmod a+x $(srcdir)/check-test-fullmode-with-stun.sh
	chmod a+x $(srcdir)/test-pseudotcp-random.sh
