#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

AM_CFLAGS = \
	-DG_LOG_DOMAIN=\"libnice\" \
	$(LIBNICE_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUPNP_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
endif

BUILT_SOURCES = \
	agent-enum-types.h \
	agent-enum-types.c

CLEANFILES += $(BUILT_SOURCES)

noinst_LTLIBRARIES = libagent.la

pkginclude_HEADERS = \
	agent.h \
	candidate.h \
	debug.h \
	address.h \
	interfaces.h \
	pseudotcp.h \
	$(NULL)

libagent_la_SOURCES = \
	address.h \
	address.c \
	debug.h \
	debug.c \
	candidate.h \
	candidate.c \
	component.h \
	component.c \
	agent.h \
	agent-priv.h \
	agent.c \
	stream.h \
	stream.c \
	conncheck.c \
	conncheck.h \
	discovery.c \
	discovery.h \
	interfaces.c \
	interfaces.h \
	pseudotcp.h \
	pseudotcp.c \
	iostream.h \
	iostream.c \
	inputstream.h \
	inputstream.c \
	outputstream.h \
	outputstream.c \
	$(BUILT_SOURCES)

agent-enum-types.h: $(pkginclude_HEADERS) Makefile
	$(AM_V_GEN)$(GLIB_MKENUMS) \
		--fhead "#ifndef __AGENT_ENUM_TYPES_H__\n#define __AGENT_ENUM_TYPES_H__ 1\n\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n" \
		--fprod "/* enumerations from \"@filename@\" */\n" \
		--vhead "GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define NICE_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n" \
		--ftail "G_END_DECLS\n\n#endif /* !AGENT_ENUM_TYPES_H */" \
		$(addprefix $(srcdir)/,$(pkginclude_HEADERS)) > $@

agent-enum-types.c: $(pkginclude_HEADERS) Makefile agent-enum-types.h
	$(AM_V_GEN)$(GLIB_MKENUMS) \
		--fhead "#include <config.h>\n#include <glib-object.h>\n#include \"agent.h\"\n#include \"pseudotcp.h\"\n#include \"agent-enum-types.h\"" \
		--fprod "\n/* enumerations from \"@filename@\" */" \
		--vhead "GType\n@enum_name@_get_type (void)\n{\n  static GType type = 0;\n  if (!type) {\n    static const G@Type@Value values[] = {" \
		--vprod "      { @VALUENAME@, \"@VALUENAME@\", \"@valuenick@\" }," \
		--vtail "      { 0, NULL, NULL }\n    };\n    type = g_@type@_register_static (\"@EnumName@\", values);\n  }\n  return type;\n}\n\n" \
		$(addprefix $(srcdir)/,$(pkginclude_HEADERS)) > $@

libagent_la_LIBADD = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la \
	$(GLIB_LIBS) \
	$(GUPNP_LIBS) \
	$(NULL)
libagent_la_DEPENDENCIES = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la

if WINDOWS
  libagent_la_LIBADD += -liphlpapi -lws2_32
endif

#
# GObject introspection
#
# We need --accept-unprefixed because of PseudoTcp and TurnServer.
#
-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir) --warn-all --accept-unprefixed
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

if HAVE_INTROSPECTION
introspection_sources = $(pkginclude_HEADERS)

Nice-0.1.gir: libagent.la
Nice_0_1_gir_INCLUDES = GObject-2.0 Gio-2.0
Nice_0_1_gir_EXPORT_PACKAGES = nice
Nice_0_1_gir_CFLAGS = $(AM_CFLAGS)
Nice_0_1_gir_LIBS = libagent.la
Nice_0_1_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += Nice-0.1.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif

EXTRA_DIST = meson.build
