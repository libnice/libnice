
AC_PREREQ(2.62)

dnl Always compile with -Wall; if --enable-compile-warnings=error is passed,
dnl also use -Werror. git and pre-releases default to -Werror

dnl use a three digit version number for releases, and four for cvs/prerelease
AC_INIT([libnice],[0.1.13])
LIBNICE_RELEASE="yes"

AC_CANONICAL_TARGET

AC_CONFIG_SRCDIR([agent/agent.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.12 -Wall -Wno-portability subdir-objects])

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
LIBNICE_CURRENT=16
LIBNICE_REVISION=2
LIBNICE_AGE=6
LIBNICE_LIBVERSION=${LIBNICE_CURRENT}:${LIBNICE_REVISION}:${LIBNICE_AGE}
LIBNICE_LT_LDFLAGS="-version-info ${LIBNICE_LIBVERSION} -no-undefined"
AC_SUBST(LIBNICE_LT_LDFLAGS)

dnl use pretty build output
AM_SILENT_RULES([yes])


# Checks for programs.

AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AM_PROG_AR
LT_PREREQ([2.2.6])
LT_INIT([dlopen win32-dll disable-static])

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
AC_CHECK_HEADERS([arpa/inet.h net/in.h netdb.h])
AC_CHECK_HEADERS([ifaddrs.h], \
		      [AC_DEFINE(HAVE_GETIFADDRS, [1], \
		       [Whether getifaddrs() is available on the system])])
AC_CHECK_TYPES([size_t, ssize_t])

# Also put matching version in LIBNICE_CFLAGS
GLIB_REQ=2.30

LIBNICE_CFLAGS="-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_2_30 -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_36"

dnl Support different levels of compiler error reporting.
dnl This configure flag is designed to mimic one from gnome-common,
dnl Defaults to "error" except for releases where it defaults to "yes"
AC_ARG_ENABLE(compile-warnings,
              AS_HELP_STRING([--enable-compile-warnings=@<:@no/minimum/yes/maximum/error@:>@],
                             [Enable different levels of compiler warnings]),,
              [AS_IF([test "$LIBNICE_RELEASE" = "yes"],
                  [enable_compile_warnings="yes"],
                  [enable_compile_warnings="error"])])

AC_DEFUN([NICE_ADD_FLAG],
  AS_COMPILER_FLAG([$1], LIBNICE_CFLAGS="$LIBNICE_CFLAGS $1", [])
)

NICE_ADD_FLAG([-fno-strict-aliasing])

AS_IF([test "$enable_compile_warnings" != "no"],[
    NICE_ADD_FLAG([-Wall])
])
AS_IF([test "x$enable_compile_warnings" != "xno" -a \
	    "x$enable_compile_warnings" != "xminimum"],[
    NICE_ADD_FLAG([-Wextra])
    NICE_ADD_FLAG([-Wundef])
    NICE_ADD_FLAG([-Wnested-externs])
    NICE_ADD_FLAG([-Wwrite-strings])
    NICE_ADD_FLAG([-Wpointer-arith])
    NICE_ADD_FLAG([-Wmissing-declarations])
    NICE_ADD_FLAG([-Wmissing-prototypes])
    NICE_ADD_FLAG([-Wstrict-prototypes])
    NICE_ADD_FLAG([-Wredundant-decls])
    NICE_ADD_FLAG([-Wno-unused-parameter])
    NICE_ADD_FLAG([-Wno-missing-field-initializers])
    NICE_ADD_FLAG([-Wdeclaration-after-statement])
    NICE_ADD_FLAG([-Wformat=2])
    NICE_ADD_FLAG([-Wold-style-definition])
    NICE_ADD_FLAG([-Wcast-align])
    NICE_ADD_FLAG([-Wformat-nonliteral])
    NICE_ADD_FLAG([-Wformat-security])
])
AS_IF([test "$enable_compile_warnings" = "yes" -o \
            "$enable_compile_warnings" = "maximum" -o \
            "$enable_compile_warnings" = "error"],[
    NICE_ADD_FLAG([-Wsign-compare])
    NICE_ADD_FLAG([-Wstrict-aliasing])
    NICE_ADD_FLAG([-Wshadow])
    NICE_ADD_FLAG([-Winline])
    NICE_ADD_FLAG([-Wpacked])
    NICE_ADD_FLAG([-Wmissing-format-attribute])
    NICE_ADD_FLAG([-Wmissing-noreturn])
    NICE_ADD_FLAG([-Winit-self])
    NICE_ADD_FLAG([-Wredundant-decls])
    NICE_ADD_FLAG([-Wmissing-include-dirs])
    NICE_ADD_FLAG([-Wunused-but-set-variable])
    NICE_ADD_FLAG([-Warray-bounds])
])
AS_IF([test "$enable_compile_warnings" = "maximum" -o \
            "$enable_compile_warnings" = "error"],[
    NICE_ADD_FLAG([-Wswitch-enum])
    NICE_ADD_FLAG([-Wswitch-default])
    NICE_ADD_FLAG([-Waggregate-return])
])
AS_IF([test "x$enable_compile_warnings" = "xerror"],[
    NICE_ADD_FLAG([-Werror])
    NICE_ADD_FLAG([-Wno-suggest-attribute=format])
])

#
# Fixes for Solaris
#
AC_SEARCH_LIBS([inet_pton],[nsl])
AC_SEARCH_LIBS([socket],[socket inet])
case $host in
	*-*-solaris* )
	AC_DEFINE(_XOPEN_SOURCE,          600, Needed to get declarations for msg_control and msg_controllen on Solaris)
	AC_DEFINE(__EXTENSIONS__,         1, Needed to get declarations for msg_control and msg_controllen on Solaris)
     ;;
esac

AC_SUBST(LIBNICE_CFLAGS)
AC_MSG_NOTICE([set LIBNICE_CFLAGS to $LIBNICE_CFLAGS])

# Checks for libraries.
AC_CHECK_LIB(rt, clock_gettime, [LIBRT="-lrt"], [LIBRT=""])
AC_CHECK_FUNCS([poll])
AC_SUBST(LIBRT)

# Dependencies
NICE_PACKAGES_PUBLIC="glib-2.0 >= $GLIB_REQ gio-2.0 >= $GLIB_REQ gobject-2.0 >= $GLIB_REQ"
NICE_PACKAGES_PRIVATE="gthread-2.0"
NICE_PACKAGES="$NICE_PACKAGES_PUBLIC $NICE_PACKAGES_PRIVATE"
AC_SUBST([NICE_PACKAGES_PUBLIC])
AC_SUBST([NICE_PACKAGES_PRIVATE])
AC_SUBST([NICE_PACKAGES])

PKG_CHECK_MODULES(GLIB, [$NICE_PACKAGES])

AC_ARG_WITH(gstreamer, 
	AS_HELP_STRING([--with-gstreamer],[build GStreamer plugin]),
	[with_gstreamer=${withval}],
	[with_gstreamer=auto])

AC_ARG_WITH(gstreamer-0.10, 
	AS_HELP_STRING([--with-gstreamer-0.10],[build GStreamer 0.10 plugin]),
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

	PKG_CHECK_MODULES(GST_CHECK, [
		gstreamer-check-1.0 >= 0.11.91
		],
		[
		have_gst_check=yes
		],
		[
		have_gst_check=no
		])

	AM_CONDITIONAL(HAVE_GST_CHECK, test "$have_gst_check" = yes)

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

GUPNP_IGD_REQUIRED=0.2.4

AC_ARG_ENABLE([gupnp],
        AS_HELP_STRING([--disable-gupnp],[Disable GUPnP IGD support]),
        [case "${enableval}" in
            yes) WANT_GUPNP=yes ;;
            no)  WANT_GUPNP=no ;;
            *) AC_MSG_ERROR(bad value ${enableval} for --enable-gupnp) ;;
        esac],
        WANT_GUPNP=test)

GUPNP_PACKAGES_PUBLIC=""
GUPNP_PACKAGES_PRIVATE="gupnp-igd-1.0 >= $GUPNP_IGD_REQUIRED"
GUPNP_PACKAGES="$GUPNP_PACKAGES_PUBLIC $GUPNP_PACKAGES_PRIVATE"

HAVE_GUPNP=no
if test "x$WANT_GUPNP" != "xno"; then
   PKG_CHECK_MODULES(GUPNP, [$GUPNP_PACKAGES],
    [ HAVE_GUPNP=yes ],
    [ HAVE_GUPNP=no ])
fi
if test "x$WANT_GUPNP" = "xyes" && test "x$HAVE_GUPNP" = "xno"; then
   AC_MSG_ERROR([Requested GUPnP IGD, but it is not available])
fi

if test "x$HAVE_GUPNP" = "xyes"; then
   AC_DEFINE(HAVE_GUPNP,,[Have the GUPnP IGD library])
  UPNP_ENABLED="true"
else
  GUPNP_PACKAGES_PUBLIC=""
  GUPNP_PACKAGES_PRIVATE=""
  GUPNP_PACKAGES=""
fi

AC_SUBST([GUPNP_PACKAGES_PUBLIC])
AC_SUBST([GUPNP_PACKAGES_PRIVATE])
AC_SUBST([GUPNP_PACKAGES])

AC_SUBST(HAVE_GUPNP)
AC_SUBST([UPNP_ENABLED])

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

dnl build static plugins or not
AC_MSG_CHECKING([whether to build static plugins or not])
AC_ARG_ENABLE(
  static-plugins,
  AC_HELP_STRING(
    [--enable-static-plugins],
    [build static plugins @<:@default=no@:>@]),
  [AS_CASE(
    [$enableval], [no], [], [yes], [],
    [AC_MSG_ERROR([bad value "$enableval" for --enable-static-plugins])])],
  [enable_static_plugins=no])
AC_MSG_RESULT([$enable_static_plugins])
if test "x$enable_static_plugins" = xyes; then
  AC_DEFINE(GST_PLUGIN_BUILD_STATIC, 1,
    [Define if static plugins should be built])
fi
AM_CONDITIONAL(GST_PLUGIN_BUILD_STATIC, test "x$enable_static_plugins" = "xyes")

case $host_os in
  solaris*)
    LDFLAGS="$LDFLAGS -lsocket -lnsl"
    ;;
  *)
    ;;
esac

# check for gtk-doc
m4_ifdef([GTK_DOC_CHECK], [
GTK_DOC_CHECK([1.9],[--flavour no-tmpl])
],[
AM_CONDITIONAL([ENABLE_GTK_DOC], false)
])

# GObject introspection
GOBJECT_INTROSPECTION_CHECK([1.30.0])

AC_CONFIG_MACRO_DIR(m4)

AC_OUTPUT

