
AC_PREREQ(2.60)
AC_INIT(nice, 0.0.1)
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([
	Makefile
	address/Makefile
	agent/Makefile
	tests/Makefile
	stun/Makefile
	local/Makefile
	udp/Makefile
	nice/Makefile
	nice/libnice.pc
	random/Makefile
	gst/Makefile
	])

# Checks for programs.

AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.

PKG_CHECK_MODULES(GLIB, [dnl
	glib-2.0 >= 2.10 dnl
	gobject-2.0 >= 2.10 dnl
	])

AC_ARG_WITH(gstreamer, 
	AC_HELP_STRING([--with-gstreamer], [use GStreamer]),
	[with_gstreamer=${withval}],
	[with_gstreamer=auto])

if test "$with_gstreamer" != no; then
	PKG_CHECK_MODULES(GST, [
		gstreamer-0.10 >= 0.10.0
		gstreamer-base-0.10 >= 0.10.0
		],
		[with_gstreamer=yes],
		[
		if test "$with_gstreamer" = yes; then
			AC_MSG_ERROR([GStreamer support was requested but GStreamer libraries are not available])
		fi

		with_gstreamer=no
		])
fi

AM_CONDITIONAL(WITH_GSTREAMER, test "$with_gstreamer" = yes)

AC_OUTPUT

