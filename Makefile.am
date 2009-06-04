SUBDIRS = lib bin

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pkgconfig/maemosec.pc pkgconfig/maemosec-certman.pc 

include_HEADERS = \
	include/maemosec_common.h \
	include/maemosec_storage.h \
	include/maemosec_certman.h

EXTRA_DIST = \
	include

DISTCLEANFILES = \
	aclocal.m4 \
	include/config.h.in \
	Makefile.in \
	configure \
	autom4te.cache/* \
	config.sub \
	config.log \
	config.status \
	config.guess \
	ltmain.sh \
	libtool \
	depcomp \
	install-sh \
	missing

