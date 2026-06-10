AC_PREREQ([2.69])
AC_INIT([netify-plugin-fwa],
    m4_esyscmd_s([cat VERSION]),
    [support@ipsquared.com])
AC_CONFIG_AUX_DIR([automake])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects 1.13])
AM_MAINTAINER_MODE([disable])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CXX
AC_PROG_CC
LT_INIT([disable-static])

AX_CXX_COMPILE_STDCXX([17], [noext], [mandatory])

PKG_CHECK_MODULES([LIBNETIFYD], [libnetifyd])
PKG_CHECK_MODULES([LIBNFTABLES], [libnftables])

AC_ARG_ENABLE([package],
    [AS_HELP_STRING([--enable-package], [build the plugin .so (needs libuci)])],
    [enable_package=$enableval], [enable_package=no])
AM_CONDITIONAL([BUILD_PACKAGE], [test "x$enable_package" = "xyes"])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
