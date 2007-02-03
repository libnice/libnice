
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
	])

# Checks for programs.

AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.

PKG_CHECK_MODULES(GLIB, [dnl
	glib-2.0 >= 2.10 dnl
	gobject-2.0 >= 2.10 dnl
	])

AC_OUTPUT

