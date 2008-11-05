
AC_PREREQ(2.59c)
AC_INIT(nice, 0.0.1.1)
AC_CONFIG_SRCDIR([agent/agent.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_FILES([
	Makefile
	agent/Makefile
	stun/Makefile
	stun/tests/Makefile
	stun/tools/Makefile
	socket/Makefile
	nice/Makefile
	nice/nice.pc
	random/Makefile
	gst/Makefile
	docs/Makefile
	docs/reference/Makefile
	docs/reference/libnice/Makefile
	])

# Set the libtool C/A/R version info
NICE_CURRENT=0
NICE_REVISION=0
NICE_AGE=0
NICE_LIBVERSION=${NICE_CURRENT}:${NICE_REVISION}:${NICE_AGE}
NICE_LT_LDFLAGS="-version-info ${NICE_LIBVERSION}"
AC_SUBST(NICE_LT_LDFLAGS)

# Checks for programs.

AC_PROG_CC
dnl AC_PROG_CC_C99
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LIBTOOL

# Checks for compiler features

AC_C_RESTRICT
AC_C_VARARRAYS
AC_HEADER_ASSERT
AC_HEADER_STDBOOL
AC_DEFINE([_FORTIFY_SOURCE], [2], [Define to `2' to get GNU/libc warnings.])
AC_DEFINE([NICEAPI_EXPORT], [ ], [Public library function implementation])
AC_CHECK_HEADERS([arpa/inet.h net/in.h ifaddrs.h])

# Checks for libraries.
AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"], [LIBRT=""])
AC_CHECK_FUNCS([poll])
AC_SUBST(LIBRT)

PKG_CHECK_MODULES(OPENSSL, [openssl])

PKG_CHECK_MODULES(GLIB, [dnl
	glib-2.0 >= 2.10 dnl
	gobject-2.0 >= 2.10 dnl
	gthread-2.0 >= 2.10 dnl
	])

AC_ARG_WITH(gstreamer, 
	AC_HELP_STRING([--with-gstreamer], [use GStreamer]),
	[with_gstreamer=${withval}],
	[with_gstreamer=auto])

AS_IF([test "$with_gstreamer" != no], [
  
	PKG_CHECK_MODULES(GST, [
		gstreamer-0.10 >= 0.10.0
		gstreamer-base-0.10 >= 0.10.0
		gstreamer-netbuffer-0.10 >= 0.10.0
		],
		[
		with_gstreamer=yes
		GST_MAJORMINOR=0.10
		gstplugindir="\$(libdir)/gstreamer-$GST_MAJORMINOR"
		],
		[
		AS_IF([test "$with_gstreamer" = yes], [
			AC_MSG_ERROR([GStreamer support was requested but GStreamer libraries are not available])
		])

		with_gstreamer=no
		])
])

AC_SUBST(gstplugindir)

AM_CONDITIONAL(WITH_GSTREAMER, test "$with_gstreamer" = yes)

dnl Test coverage
AC_ARG_ENABLE([coverage],
	[AS_HELP_STRING([--enable-coverage],
		[build for test coverage (default disabled)])],,
	[enable_coverage="no"])
AS_IF([test "${enable_coverage}" != "no"], [
	CFLAGS="${CFLAGS} -g -O0 -fprofile-arcs -ftest-coverage"
	LDFLAGS="-lgcov"
	CCACHE_DISABLE=1
])
AC_SUBST(CCACHE_DISABLE)

# check for gtk-doc
GTK_DOC_CHECK(1.9)
AC_CONFIG_MACRO_DIR(m4)

AC_OUTPUT

