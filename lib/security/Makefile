include ../../make/Makefile.inc

LDFLAGS+= -lssl
CPPFLAGS+= -I ../../include

# Targets
OBJS=sec_common.o sec_storage.o
LIB=../libngswsecurity.a

$(LIB): $(OBJS)

clean:
	$(CLEAN_OBJS)
