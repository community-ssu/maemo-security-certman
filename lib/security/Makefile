include ../../make/Makefile.inc

# LDFLAGS+= -lssl -lexpat
LDFLAGS+= -lssl
CPPFLAGS+= -I ../../include

# Targets
OBJS=sec_common.o sec_storage.o c_fstring.o c_map.o c_wordlist.o c_xmlnode.o c_xmldoc.o
LIB=../libngswsecurity.a
SOLIB=libngswsecurity.so.1.0

all: $(LIB) ../$(SOLIB)

$(LIB): $(OBJS)

../$(SOLIB): $(OBJS)
	g++ -o $@ $(LDFLAGS) -Os -Wall -shared -Wl,-soname,$(SOLIB)  $^

clean:
	$(CLEAN_OBJS)
