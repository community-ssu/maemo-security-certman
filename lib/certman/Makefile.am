INCLUDES = -I../../include -I../security

lib_LTLIBRARIES = libmaemosec_certman.la

libmaemosec_certman_la_SOURCES = \
 ../../include/libbb5.h ../../include/libbb5stub.h \
 ../../include/libcertman.h ngcm_main.cpp \
 ngcm_x509_cert.h ngcm_x509_cert.cpp \
 ngcm_config.h ngcm_config.cpp \
 pkcs11.h pkcs11f.h pkcs11f-partial.h pkcs11t.h pkcs11n.h ngcm_cryptoki.h ngcm_cryptoki.c

# Include all necessary libraries in the .so so that it can be used
# as a PCKS#11 plugin
libmaemosec_certman_la_LIBADD = -lcrypto -lssl -lexpat \
 -L../libbb5/.libs -lbb5 \
 -L../security/.libs -lmaemosec

