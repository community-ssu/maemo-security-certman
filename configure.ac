dnl AC_PREREQ(2.59)
AC_INIT([maemo-security-certman], [0.2.4])
dnl AC_CONFIG_SRCDIR(lib/certman/maemosec_certman_main.cpp)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AC_CONFIG_HEADERS(include/config.h)
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(OPENSSL, [ openssl >= 0.9.8 ])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

dnl Scratchbox uses a different naming convention
dnl than the rest of the world
PKG_CHECK_MODULES(NSS, [ mozilla-nss >= 1.0.1 ])
# NSS_CFLAGS=`echo $NSS_CFLAGS | sed 's/\/stable/\/nspr/'`
AC_SUBST(NSS_CFLAGS)
AC_SUBST(NSS_LIBS)

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6.0)
AC_SUBST(GLIB_LIBS)
AC_SUBST(GLIB_CFLAGS)
                                                                                
PKG_CHECK_MODULES(OSSO, libosso >= 1.0.0)
AC_SUBST(OSSO_LIBS)
AC_SUBST(OSSO_CFLAGS)

AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/conf.h)
AC_CONFIG_FILES(pkgconfig/maemosec.pc:pkgconfig/maemosec.pc.in)
AC_CONFIG_FILES(pkgconfig/maemosec-certman.pc:pkgconfig/maemosec-certman.pc.in)
AC_PROG_MAKE_SET
AC_OUTPUT([
Makefile 
lib/Makefile
lib/security/Makefile 
lib/certman/Makefile 
bin/Makefile
bin/cli/Makefile
])
