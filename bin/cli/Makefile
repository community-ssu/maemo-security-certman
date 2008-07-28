# Test programs

include ../../make/Makefile.inc

LDFLAGS+=-lssl -lstdc++
CFLAGS+= -I../../include
CPPFLAGS+= -I../../include -I../../lib/security
LIBS=../../lib/libngswsecurity.a ../../lib/libbb5.a

all: sscli cmcli xmlpp

sscli : sscli.o $(LIBS)

xmlpp : xmlpp.o $(LIBS) /usr/lib/libexpat.a 

cmcli : cmcli.o ../../lib/libngswcertman.a $(LIBS)

clean :
	$(CLEAN_OBJS)
	@rm -f cmcli sscli