AC_INIT([ap-notify], [1.0], [dan@danweeks.net])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_SRCDIR([src])

AC_PROG_CC_C99

PKG_CHECK_MODULES([LIBNL], [libnl-3.0])

# for older version of
AC_SUBST([LIBNL_CFLAGS])
AC_SUBST([LIBNL_LIBS])

PKG_CHECK_MODULES([LIBNL_GENL],[libnl-genl-3.0])

# for older version of
AC_SUBST([LIBNL_GENL_CFLAGS])
AC_SUBST([LIBNL_GENL_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
