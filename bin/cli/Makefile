include ../../make/Makefile.inc

LDFLAGS+= -L ../../lib -lssl -lstdc++
CFLAGS+= -I../../include
CPPFLAGS+= -I../../include
LIBS=../../lib/libngswsecurity.a ../../lib/libbb5.a

all: sscli cmcli

sscli : sscli.o $(LIBS)

cmcli : cmcli.o ../../lib/libngswcertman.a $(LIBS) 

clean :
	$(CLEAN_OBJS)
	@rm -f cmcli sscli