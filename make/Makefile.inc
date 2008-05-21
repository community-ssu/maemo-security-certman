%.a : 
	ar -r $@ $^

%.so.% :
	g++ -shared -Wl,-soname,$(F) -g -o $@ $^ -lc

# CLEAN_OBJS=for p in *.o ; do if [ -f $$p ] ; then rm -f $$p ; fi ; done

CLEAN_OBJS=@rm -f *.o

LDFLAGS+=-g
CFLAGS+=-g
CPPFLAGS+=-g