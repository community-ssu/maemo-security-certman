include ../../make/Makefile.inc

# LDFLAGS+= -lssl -lexpat
LDFLAGS+= -lssl
CPPFLAGS+= -I ../../include

# Targets
# OBJS=sec_common.o sec_storage.o c_fstring.o c_map.o c_wordlist.o c_xmlnode.o c_xmldoc.o
OBJS=sec_common.o sec_storage.o
LIB=../libngswsecurity.a

$(LIB): $(OBJS)

clean:
	$(CLEAN_OBJS)
