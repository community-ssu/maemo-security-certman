INCLUDES = -I../../include -I../../lib/security ${NSS_CFLAGS} ${OPENSSL_CFLAGS}

bin_PROGRAMS = sscli cmcli xmlpp dlog b64

sscli_SOURCES = sscli.cpp
sscli_LDADD =  -L../../lib/security/.libs -lmaemosec

cmcli_SOURCES = cmcli.c
cmcli_LDADD =  -L../../lib/security/.libs -lmaemosec \
 -L../../lib/certman/.libs -lmaemosec_certman ${OPENSSL_LIBS}

xmlpp_SOURCES = xmlpp.cpp
xmlpp_LDADD =  -L../../lib/security/.libs -lmaemosec

dlog_SOURCES = dlog.c

b64_SOURCES = b64.c
b64_LDADD = -L../../lib/security/.libs -lmaemosec
