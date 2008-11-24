INCLUDES = -I../../include -I../../lib/security

bin_PROGRAMS = sscli cmcli xmlpp dlog

sscli_SOURCES = sscli.cpp
sscli_LDADD =  -L../../lib/libbb5/.libs -lbb5 \
 -L../../lib/security/.libs -lmaemosec

cmcli_SOURCES = cmcli.c
cmcli_LDADD =  -L../../lib/security/.libs -lmaemosec \
 -L../../lib/certman/.libs -lmaemosec_certman

xmlpp_SOURCES = xmlpp.cpp
xmlpp_LDADD =  -L../../lib/security/.libs -lmaemosec

dlog_SOURCES = dlog.c

