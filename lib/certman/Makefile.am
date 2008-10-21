INCLUDES = -I../../include -I../security

lib_LTLIBRARIES = libmaemosec_certman.la

libmaemosec_certman_la_SOURCES = \
 ../../include/libbb5.h ../../include/libbb5stub.h \
 ../../include/maemosec_certman.h certman_main.cpp \
 x509_container.h x509_container.cpp \
 cryptoki_config.h cryptoki_config.cpp \
 cryptoki_module.h cryptoki_module.c \
 pkcs11.h pkcs11f.h pkcs11f-partial.h pkcs11t.h pkcs11n.h

# Include all necessary libraries in the .so so that it can be used
# as a PCKS#11 plugin
libmaemosec_certman_la_LIBADD = -lcrypto \
 -L../libbb5/.libs -lbb5 \
 -L../security/.libs -lmaemosec

