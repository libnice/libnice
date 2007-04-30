#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = $(ERROR_CFLAGS) $(GLIB_CFLAGS)

LIBS = $(GLIB_LIBS)

noinst_LTLIBRARIES = libstun.la

libstun_la_SOURCES = stun.h stun.c

noinst_PROGRAMS = stun-client stun-server

stun_client_LDADD = libstun.la
stun_server_LDADD = libstun.la

check_PROGRAMS = \
	test-attribute-pack \
	test-attribute-pack-unknown \
	test-attribute-dump \
	test-attribute-dump-unknown \
	test-attribute-unpack \
	test-attribute-unpack-unknown \
	test-attribute-unpack-wrong-length \
	test-message-pack \
	test-message-dump \
	test-message-dump-unknown \
	test-message-unpack \
	test-message-find-attribute

test_attribute_pack_LDADD                = libstun.la
test_attribute_pack_unknown_LDADD        = libstun.la
test_attribute_dump_LDADD                = libstun.la
test_attribute_dump_unknown_LDADD        = libstun.la
test_attribute_unpack_LDADD              = libstun.la
test_attribute_unpack_unknown_LDADD      = libstun.la
test_attribute_unpack_wrong_length_LDADD = libstun.la
test_message_pack_LDADD                  = libstun.la
test_message_dump_LDADD                  = libstun.la
test_message_dump_unknown_LDADD          = libstun.la
test_message_unpack_LDADD                = libstun.la
test_message_find_attribute_LDADD        = libstun.la

TESTS = $(check_PROGRAMS)

