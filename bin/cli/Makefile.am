INCLUDES = -I../../include -I../../lib/security

bin_PROGRAMS = cmcli sscli xmlpp

cmcli_SOURCES = cmcli.c
cmcli_LDADD =  -L../../lib/libbb5/.libs -lbb5\
 -L../../lib/security/.libs -lmaemosec\
 -L../../lib/certman/.libs -lmaemosec_certman\
 -lssl -lexpat

sscli_SOURCES = sscli.cpp
sscli_LDADD =  -L../../lib/libbb5/.libs -lbb5\
 -L../../lib/security/.libs -lmaemosec\
 -lssl -lexpat

xmlpp_SOURCES = xmlpp.cpp
xmlpp_LDADD =  -L../../lib/libbb5/.libs -lbb5\
 -L../../lib/security/.libs -lmaemosec\
 -lssl -lexpat
