INCLUDES = -I../../include

lib_LTLIBRARIES = libmaemosec.la

libmaemosec_la_SOURCES = \
 ../../include/libbb5.h ../../include/libbb5stub.h \
 ../../include/sec_common.h sec_common.cpp \
 ../../include/sec_storage.h sec_storage.cpp \
 c_xmlnode.h c_xmlnode.cpp \
 c_xmldoc.h c_xmldoc.cpp

libmaemosec_la_LIBADD = -lcrypto -lssl -lexpat \
 -L../libbb5/.libs -lbb5
