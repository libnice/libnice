
AC_PREREQ(2.60)
AC_INIT(stun, 0.0.1)
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([
	Makefile
	tests/Makefile
	stun/Makefile
	])

# Checks for programs.

AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

PKG_CHECK_MODULES(CHECK, [dnl
	check >= 0.9.4 dnl
	])

PKG_CHECK_MODULES(GLIB, [dnl
	glib-2.0 >= 2.4 dnl
	gobject-2.0 >= 2.4 dnl
	])

AC_OUTPUT

