# Test programs

BINS=sscli cmcli xmlpp

include ../../make/Makefile.inc

LDFLAGS+=-lssl -lstdc++
CFLAGS+= -I../../include
CPPFLAGS+= -I../../include -I../../lib/security
LIBS=../../lib/libngswsecurity.a ../../lib/libbb5.a

all: $(BINS)

sscli : sscli.o $(LIBS)

xmlpp : xmlpp.o $(LIBS) /usr/lib/libexpat.a 

cmcli : cmcli.o ../../lib/libngswcertman.a $(LIBS)

# cmcli-dyn : cmcli.o
#	cc -o cmcli-dyn -g -lssl -lstdc++ -L../../lib -lngswcertman $^
clean :
	$(CLEAN_OBJS)
	@rm -f $(BINS)
