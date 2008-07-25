include ../../make/Makefile.inc

CPPFLAGS+=-I ../../include -I ../security

# Targets
OBJS=ngcm_main.o ngcm_x509_cert.o ngcm_config.o ngcm_cryptoki.o
LIB=../libngswcertman.a
SOLIB=libngswcertman.so.1.0

all: $(LIB) ../$(SOLIB)

$(LIB): $(OBJS)

../$(SOLIB): $(OBJS) ../security/sec_common.o ../security/sec_storage.o ../libbb5/libbb5stub.o
	g++ -o $@ -Os -Wall -shared -Wl,-soname,$(SOLIB) -L.. $^

clean:
	$(CLEAN_OBJS)
