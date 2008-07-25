include ../../make/Makefile.inc

LDFLAGS+= -L ../../lib -lssl -lstdc++ -lngswsecurity -lngswcertman
CFLAGS+= -I../../include
CPPFLAGS+= -I../../include
LIBS=../../lib/libbb5.a

all: sscli cmcli

sscli : sscli.o $(LIBS)

cmcli : cmcli.o $(LIBS) 

clean :
	$(CLEAN_OBJS)
	@rm -f cmcli sscli