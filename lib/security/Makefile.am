INCLUDES = -I../../include

lib_LTLIBRARIES = libmaemosec.la

libmaemosec_la_SOURCES = \
 ../../include/libbb5.h ../../include/libbb5stub.h \
 ../../include/maemosec_common.h maemosec_common.cpp \
 ../../include/maemosec_storage.h maemosec_storage.cpp \
 c_xmlnode.h c_xmlnode.cpp \
 c_xmldoc.h c_xmldoc.cpp \
 dlog_send.c

libmaemosec_la_LIBADD = -lcrypto -lexpat \
 -L../libbb5/.libs -lbb5
