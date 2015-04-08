#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

TESTS_ENVIRONMENT=\
	GST_PLUGIN_PATH=${GST_PLUGIN_PATH}:$(top_builddir)/gst

AM_CFLAGS = \
	$(LIBNICE_CFLAGS) \
	$(GLIB_CFLAGS) \
        $(GUPNP_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun
AM_CPPFLAGS = -DG_LOG_DOMAIN=\"libnice-tests\"

COMMON_LDADD = $(top_builddir)/agent/libagent.la $(top_builddir)/socket/libsocket.la $(GLIB_LIBS) $(GUPNP_LIBS)

check_PROGRAMS = \
	test-pseudotcp \
	test-pseudotcp-fin \
	test-pseudotcp-fuzzy \
	test-bsd \
	test \
	test-address \
	test-add-remove-stream \
	test-build-io-stream \
	test-io-stream-thread \
	test-io-stream-closing-write \
	test-io-stream-closing-read \
	test-io-stream-cancelling \
	test-io-stream-pollable \
	test-send-recv \
	test-priority \
	test-mainloop \
	test-fullmode \
	test-restart \
	test-fallback \
	test-thread \
	test-dribble \
	test-new-dribble \
	test-tcp \
	test-icetcp \
	test-credentials

dist_check_SCRIPTS = \
	check-test-fullmode-with-stun.sh \
	test-pseudotcp-random.sh

if HAVE_GST_CHECK
check_PROGRAMS += test-gstreamer
endif

TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)

noinst_HEADERS = test-io-stream-common.h

test_pseudotcp_LDADD = $(COMMON_LDADD)

test_pseudotcp_fin_LDADD = $(COMMON_LDADD)

test_pseudotcp_fuzzy_LDADD = $(COMMON_LDADD) -lm

test_bsd_LDADD = $(COMMON_LDADD)

test_LDADD = $(COMMON_LDADD)

test_thread_LDADD = $(COMMON_LDADD)

test_address_LDADD = $(COMMON_LDADD)

test_add_remove_stream_LDADD = $(COMMON_LDADD)

test_build_io_stream_LDADD = $(COMMON_LDADD)

test_io_stream_thread_SOURCES = test-io-stream-thread.c test-io-stream-common.c
test_io_stream_thread_LDADD = $(COMMON_LDADD)

test_io_stream_closing_write_SOURCES = test-io-stream-closing-write.c test-io-stream-common.c
test_io_stream_closing_write_LDADD = $(COMMON_LDADD)

test_io_stream_closing_read_SOURCES = test-io-stream-closing-read.c test-io-stream-common.c
test_io_stream_closing_read_LDADD = $(COMMON_LDADD)

test_io_stream_cancelling_SOURCES = test-io-stream-cancelling.c test-io-stream-common.c
test_io_stream_cancelling_LDADD = $(COMMON_LDADD)

test_io_stream_pollable_SOURCES = test-io-stream-pollable.c test-io-stream-common.c
test_io_stream_pollable_LDADD = $(COMMON_LDADD)

test_send_recv_SOURCES = test-send-recv.c test-io-stream-common.c
test_send_recv_LDADD = $(COMMON_LDADD)

test_priority_LDADD = $(COMMON_LDADD)

test_mainloop_LDADD = $(COMMON_LDADD)

test_fullmode_LDADD = $(COMMON_LDADD)

test_restart_LDADD = $(COMMON_LDADD)

test_fallback_LDADD = $(COMMON_LDADD)

test_dribble_LDADD = $(COMMON_LDADD)

test_new_dribble_LDADD = $(COMMON_LDADD)

test_tcp_LDADD = $(COMMON_LDADD)

test_icetcp_LDADD = $(COMMON_LDADD)

test_credentials_LDADD = $(COMMON_LDADD)

test_gstreamer_CFLAGS = $(AM_CFLAGS) $(GST_CHECK_CFLAGS)
test_gstreamer_LDADD = -lnice -L$(top_builddir)/nice/.libs $(GLIB_LIBS) $(GUPNP_LIBS) $(GST_CHECK_LIBS) $(GST_LIBS)

all-local:
	chmod a+x $(srcdir)/check-test-fullmode-with-stun.sh
	chmod a+x $(srcdir)/test-pseudotcp-random.sh

EXTRA_DIST = libnice.supp
