## Process this file with automake to produce Makefile.in

# We require automake 1.6 at least.
AUTOMAKE_OPTIONS = 1.6

# The name of the module, e.g. 'glib'.
DOC_MODULE=libnice

# The top-level SGML file. You can change this if you want to.
DOC_MAIN_SGML_FILE=$(DOC_MODULE)-docs.xml

# The directory containing the source code. Relative to $(srcdir).
# gtk-doc will search all .c & .h files beneath here for inline comments
# documenting the functions and macros.
# e.g. DOC_SOURCE_DIR=../../../gtk
DOC_SOURCE_DIR=$(top_srcdir)/agent $(top_srcdir)/stun

# Extra options to pass to gtkdoc-scangobj. Not normally needed.
SCANGOBJ_OPTIONS=

# Extra options to supply to gtkdoc-scan.
# e.g. SCAN_OPTIONS=--deprecated-guards="GTK_DISABLE_DEPRECATED"
SCAN_OPTIONS=--rebuild-types

# Extra options to supply to gtkdoc-mkdb.
# e.g. MKDB_OPTIONS=--sgml-mode --output-format=xml
MKDB_OPTIONS=--xml-mode --output-format=xml --name-space=Nice

# Extra options to supply to gtkdoc-mktmpl
# e.g. MKTMPL_OPTIONS=--only-section-tmpl
MKTMPL_OPTIONS=

# Extra options to supply to gtkdoc-fixref. Not normally needed.
# e.g. FIXXREF_OPTIONS=--extra-dir=../gdk-pixbuf/html --extra-dir=../gdk/html
FIXXREF_OPTIONS=

# Used for dependencies. The docs will be rebuilt if any of these change.
# e.g. HFILE_GLOB=$(top_srcdir)/gtk/*.h
# e.g. CFILE_GLOB=$(top_srcdir)/gtk/*.c
HFILE_GLOB=$(top_srcdir)/agent/agent.h $(top_srcdir)/agent/address.h \
	$(top_srcdir)/agent/debug.h $(top_srcdir)/agent/candidate.h \
	$(top_srcdir)/agent/interfaces.h \
	$(top_srcdir)/agent/pseudotcp.h \
	$(top_srcdir)/stun/stunagent.h  \
	$(top_srcdir)/stun/stunmessage.h \
	$(top_srcdir)/stun/debug.h \
	$(top_srcdir)/stun/usages/bind.h \
	$(top_srcdir)/stun/usages/ice.h \
	$(top_srcdir)/stun/usages/timer.h \
	$(top_srcdir)/stun/usages/turn.h

CFILE_GLOB=$(top_srcdir)/agent/agent.c \
	$(top_srcdir)/agent/pseudotcp.c

# Header files to ignore when scanning.
# e.g. IGNORE_HFILES=gtkdebug.h gtkintl.h
IGNORE_HFILES= conncheck.h discovery.h stream.h component.h agent-priv.h \
	iostream.h inputstream.h outputstream.h \
	gstnice.h gstnicesrc.h gstnicesink.h  \
	md5.h sha1.h stunhmac.h utils.h rand.h stun5389.h stuncrc32.h \
	stund.h agent-signals-marshal.h win32_common.h

# Images to copy into HTML directory.
# e.g. HTML_IMAGES=$(top_srcdir)/gtk/stock-icons/stock_about_24.png
HTML_IMAGES=

# Extra SGML files that are included by $(DOC_MAIN_SGML_FILE).
# e.g. content_files=running.sgml building.sgml changes-2.0.sgml
content_files=

# SGML files where gtk-doc abbrevations (#GtkWidget) are expanded
# These files must be listed here *and* in content_files
# e.g. expand_content_files=running.sgml
expand_content_files=

# CFLAGS and LDFLAGS for compiling gtkdoc-scangobj with your library.
# Only needed if you are using gtkdoc-scangobj to dynamically query widget
# signals and properties.
# e.g. INCLUDES=-I$(top_srcdir) -I$(top_builddir) $(GTK_DEBUG_FLAGS)
# e.g. GTKDOC_LIBS=$(top_builddir)/gtk/$(gtktargetlib)
AM_CFLAGS =  $(LIBNICE_CFLAGS) \
        $(GLIB_CFLAGS) \
        -I $(top_srcdir) \
        -I $(top_srcdir)/random \
        -I $(top_srcdir)/socket \
        -I $(top_srcdir)/stun

GTKDOC_LIBS= $(top_builddir)/agent/libagent.la $(GLIB_LIBS) $(top_builddir)/stun/libstun.la \
	 $(GUPNP_LIBS)


# This includes the standard gtk-doc make rules, copied by gtkdocize.
include $(top_srcdir)/gtk-doc.make

# Other files to distribute
# e.g. EXTRA_DIST += version.xml.in
#EXTRA_DIST +=

# Files not to distribute
# for --rebuild-types in $(SCAN_OPTIONS), e.g. $(DOC_MODULE).types
# for --rebuild-sections in $(SCAN_OPTIONS) e.g. $(DOC_MODULE)-sections.txt
#DISTCLEANFILES +=

if ENABLE_GTK_DOC
TESTS_ENVIRONMENT = cd $(builddir) &&
TESTS = $(GTKDOC_CHECK)
endif
