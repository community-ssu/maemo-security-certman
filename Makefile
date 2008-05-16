# Top-level makefile of the ngswsecurity project. 
# Just to get things started, will probably be replaced
# by autotools later.

# Some common rules first

# Common settings
CPPFLAGS += -Wall -O0 -g
LDFLAGS=-g

# Directory tree
SUBDIRS=lib bin

all:
	@for d in $(SUBDIRS) ; do if [ -d $$d ] ; then cd $$d ; make ; cd .. ; fi ; done

clean:
	@for d in $(SUBDIRS) ; do if [ -d $$d ] ; then cd $$d ; make clean ; cd .. ; fi ; done

doc:
	doxygen doc/doxygen.cfg
