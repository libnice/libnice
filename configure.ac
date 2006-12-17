
AC_PREREQ(2.60)
AC_INIT(stun, 0.0.1)
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AC_CONFIG_FILES([Makefile tests/Makefile])

# Checks for programs.

AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

AM_PATH_CHECK()

PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.4, gobject-2.0 >= 2.4])

AC_OUTPUT

