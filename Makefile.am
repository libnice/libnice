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

