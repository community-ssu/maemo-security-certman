INCLUDES = -I../../include -I../../lib/security $(MICROB_CFLAGS)

bin_PROGRAMS = sscli cmcli xmlpp dlog nsscfg

sscli_SOURCES = sscli.cpp
sscli_LDADD =  -L../../lib/libbb5/.libs -lbb5 \
 -L../../lib/security/.libs -lmaemosec

cmcli_SOURCES = cmcli.c
cmcli_LDADD =  -L../../lib/security/.libs -lmaemosec \
 -L../../lib/certman/.libs -lmaemosec_certman

xmlpp_SOURCES = xmlpp.cpp
xmlpp_LDADD =  -L../../lib/security/.libs -lmaemosec

dlog_SOURCES = dlog.c

nsscfg_SOURCES = nsscfg.c
nsscfg_LDADD = -L../../lib/libbb5/.libs -lbb5 $(MICROB_LIBS)
