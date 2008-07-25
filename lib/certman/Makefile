include ../../make/Makefile.inc

CPPFLAGS+=-I ../../include -I ../security
LDFLAGS+= -lssl -L .. -lngswsecurity

# Targets
OBJS=ngcm_main.o ngcm_x509_cert.o ngcm_config.o ngcm_cryptoki.o
LIB=../libngswcertman.a
SOLIB=libngswcertman.so.1.0

all: $(LIB) ../$(SOLIB)

$(LIB): $(OBJS)

../$(SOLIB): $(OBJS) ../libbb5/libbb5stub.o
	g++ -o $@ $(LDFLAGS) -Os -Wall -shared -Wl,-soname,$(SOLIB) $^

clean:
	$(CLEAN_OBJS)
