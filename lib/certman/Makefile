include ../../make/Makefile.inc

CPPFLAGS+=-I ../../include -I ../security
# LDFLAGS+= -lssl -L .. -lngswsecurity
LDFLAGS+= -lssl
LIBS=../libngswsecurity.a

# Targets
OBJS=ngcm_main.o ngcm_x509_cert.o ngcm_config.o ngcm_cryptoki.o
LIB=../libngswcertman.a
SOLIB=libngswcertman.so.1.0

all: $(LIB) ../$(SOLIB)

$(LIB): $(OBJS)

../$(SOLIB): $(OBJS) ../security/sec_common.o ../security/sec_storage.o ../libbb5/libbb5stub.o \
  ../security/c_fstring.o ../security/c_map.o ../security/c_wordlist.o \
  ../security/c_xmlnode.o ../security/c_xmldoc.o /usr/lib/libexpat.a
	g++ -g -o $@ -Os -Wall -shared -Wl,-soname,$(SOLIB) -static $^

clean:
	$(CLEAN_OBJS)
