
AC_PREREQ(2.59c)

dnl releases only do -Wall, cvs and prerelease does -Werror too
dnl use a three digit version number for releases, and four for cvs/prerelease
AC_INIT(libnice, 0.1.4)
LIBNICE_RELEASE="yes"

AC_CANONICAL_SYSTEM

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
	tests/Makefile
	examples/Makefile
	])

# Set the libtool C/A/R version info
#    If the source code was changed, but there were no interface changes:
#      Increment REVISION.
#    If there was a compatible interface change:
#      Increment CURRENT and AGE. Set REVISION to 0
#    If there was an incompatible interface change:
#      Increment CURRENT. Set AGE and REVISION to 0
LIBNICE_CURRENT=12
LIBNICE_REVISION=0
LIBNICE_AGE=2
LIBNICE_LIBVERSION=${LIBNICE_CURRENT}:${LIBNICE_REVISION}:${LIBNICE_AGE}
LIBNICE_LT_LDFLAGS="-version-info ${LIBNICE_LIBVERSION} -no-undefined"
AC_SUBST(LIBNICE_LT_LDFLAGS)


dnl use pretty build output with automake >= 1.11
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])


# Checks for programs.

AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_LIBTOOL

# Check Operating System
AC_MSG_CHECKING([operating system])
case "$host" in
	*-*-*mingw*|*-*-*cygwin*)
		platform=win32
		AC_MSG_RESULT($platform)
		;;
	*)
		platform=linux/other
		AC_MSG_RESULT($platform)
		;;
esac

AM_CONDITIONAL([WINDOWS], [test "$platform" = "win32"])

# Checks for compiler features

AC_C_RESTRICT
AC_C_VARARRAYS
AC_HEADER_ASSERT
AC_HEADER_STDBOOL
AH_VERBATIM([_FORTIFY_SOURCE], 
[/* Define to `2' to get GNU/libc warnings. */
/* Only define if -O1 or more is enabled */
#if defined __OPTIMIZE__ && __OPTIMIZE__ > 0
# define _FORTIFY_SOURCE 2
#endif])
AC_DEFINE([NICEAPI_EXPORT], [ ], [Public library function implementation])
AC_CHECK_HEADERS([arpa/inet.h net/in.h])
AC_CHECK_HEADERS([ifaddrs.h], \
		      [AC_DEFINE(HAVE_GETIFADDRS, [1], \
		       [Whether getifaddrs() is available on the system])])

LIBNICE_CFLAGS="-Wall"
dnl if asked for, add -Werror if supported
if test "x$LIBNICE_RELEASE" != "xyes"; then
  LIBNICE_CFLAGS="$LIBNICE_CFLAGS -Werror"
fi

AC_SUBST(LIBNICE_CFLAGS)
AC_MSG_NOTICE([set LIBNICE_CFLAGS to $LIBNICE_CFLAGS])

# Checks for libraries.
AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"], [LIBRT=""])
AC_CHECK_FUNCS([poll])
AC_SUBST(LIBRT)

PKG_CHECK_MODULES(GLIB, [dnl
	glib-2.0 >= 2.13 dnl
	gobject-2.0 >= 2.13 dnl
	gthread-2.0 >= 2.13 dnl
	gio-2.0 >= 2.13 dnl
	])

AC_ARG_WITH(gstreamer, 
	AC_HELP_STRING([--with-gstreamer], [build GStreamer plugin]),
	[with_gstreamer=${withval}],
	[with_gstreamer=auto])

AC_ARG_WITH(gstreamer-0.10, 
	AC_HELP_STRING([--with-gstreamer-0.10], [build GStreamer 0.10 plugin]),
	[with_gstreamer010=${withval}],
	[with_gstreamer010=auto])

AS_IF([test "$with_gstreamer" != no], [
  
	PKG_CHECK_MODULES(GST, [
		gstreamer-1.0 >= 0.11.91
		gstreamer-base-1.0 >= 0.11.91
		],
		[
		with_gstreamer=yes
		GST_MAJORMINOR=1.0
		gstplugindir="\$(libdir)/gstreamer-$GST_MAJORMINOR"
		],
		[
		AS_IF([test "$with_gstreamer" = yes], [
			AC_MSG_ERROR([GStreamer 1.0 support was requested but GStreamer 1.0 libraries are not available])
		])

		with_gstreamer=no
		])
])

AS_IF([test "$with_gstreamer010" != no], [
  
	PKG_CHECK_MODULES(GST010, [
		gstreamer-0.10 >= 0.10.10
		gstreamer-base-0.10 >= 0.10.10
		],
		[
		with_gstreamer010=yes
		GST_MAJORMINOR=0.10
		gstplugin010dir="\$(libdir)/gstreamer-$GST_MAJORMINOR"
		],
		[
		AS_IF([test "$with_gstreamer010" = yes], [
			AC_MSG_ERROR([GStreamer 0.10 support was requested but GStreamer 0.10 libraries are not available])
		])

		with_gstreamer010=no
		])
])

AC_SUBST(gstplugindir)
AC_SUBST(gstplugin010dir)

AM_CONDITIONAL(WITH_GSTREAMER, test "$with_gstreamer" = yes)
AM_CONDITIONAL(WITH_GSTREAMER010, test "$with_gstreamer010" = yes)

GUPNP_IGD_REQUIRED=0.1.2

AC_ARG_ENABLE([gupnp],
        AC_HELP_STRING([--disable-gupnp], [Disable GUPnP IGD support]),
        [case "${enableval}" in
            yes) WANT_GUPNP=yes ;;
            no)  WANT_GUPNP=no ;;
            *) AC_MSG_ERROR(bad value ${enableval} for --enable-gupnp) ;;
        esac],
        WANT_GUPNP=test)

HAVE_GUPNP=no
if test "x$WANT_GUPNP" != "xno"; then
   PKG_CHECK_MODULES(GUPNP, gupnp-igd-1.0 >= $GUPNP_IGD_REQUIRED,
    [ HAVE_GUPNP=yes ],
    [ HAVE_GUPNP=no ])
fi
if test "x$WANT_GUPNP" = "xyes" && test "x$HAVE_GUPNP" = "xno"; then
   AC_ERROR([Requested GUPnP IGD, but it is not available])
fi

if test "x$HAVE_GUPNP" = "xyes"; then
   AC_DEFINE(HAVE_GUPNP,,[Have the GUPnP IGD library])
fi

AC_SUBST(HAVE_GUPNP)

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

case $host_os in
  solaris*)
    LDFLAGS="$LDFLAGS -lsocket -lnls"
    ;;
  *)
    ;;
esac

# check for gtk-doc
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK(1.9)
],[
AM_CONDITIONAL([ENABLE_GTK_DOC], false)
])
AC_CONFIG_MACRO_DIR(m4)

AC_OUTPUT

