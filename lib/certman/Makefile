include ../../make/Makefile.inc

CFLAGS+=-fPIC -Wall
CPPFLAGS+=-I ../../include -I ../security -fPIC
LDFLAGS+= -lssl

# Targets
OBJS=ngcm_main.o ngcm_x509_cert.o ngcm_config.o ngcm_cryptoki.o
LIB=../libngswcertman.a
SOLIB=libngswcertman.so.1.0

all: $(LIB) ../$(SOLIB)

$(LIB): $(OBJS)

../$(SOLIB): $(OBJS) ../libngswsecurity.a ../libbb5.a
	g++ -g -o $@ -Wall -shared -Wl,-soname,$(SOLIB) $^ -lexpat -lssl

clean:
	$(CLEAN_OBJS)
