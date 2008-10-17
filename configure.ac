dnl AC_PREREQ(2.59)
AC_INIT([maemo-security-certman], [0.0.1])
AC_CONFIG_SRCDIR(lib/certman/ngcm_main.cpp)
AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AC_CONFIG_HEADERS(include/config.h)
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_LIBTOOL
dnl PKG_CHECK_MODULES(MAEMOCERTMAN, openssl >= 0.9.8e expat)
dnl AC_CHECK_LIB(ssl, CRYPTO_malloc_init)
AC_CHECK_HEADER(unistd.h)
AC_CHECK_HEADERS(openssl/conf.h)
AC_CONFIG_FILES(pkgconfig/maemosec.pc:pkgconfig/maemosec.pc.in)
AC_CONFIG_FILES(pkgconfig/maemosec-certman.pc:pkgconfig/maemosec-certman.pc.in)
AC_PROG_MAKE_SET
AC_OUTPUT([
Makefile 
lib/Makefile
lib/libbb5/Makefile 
lib/security/Makefile 
lib/certman/Makefile 
bin/Makefile
bin/cli/Makefile
])
