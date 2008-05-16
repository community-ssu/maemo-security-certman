include ../../make/Makefile.inc

LDFLAGS+= -L ../../lib -lssl -lstdc++
CFLAGS+= -I../../include
CPPFLAGS+= -I../../include
LIBS=../../lib/libngswsecurity.a ../../lib/libbb5.a

sscli : sscli.o $(LIBS)

cmcli : cmcli.o $(LIBS) ../../lib/libngswcertman.a

clean :
	$(CLEAN_OBJS)
	@rm -f cmcli sscli