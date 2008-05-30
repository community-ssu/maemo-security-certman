SUBDIRS=libbb5 security certman

all:
	@for d in $(SUBDIRS) ; do if [ -d $$d ] ; then cd $$d ; make ; cd .. ; fi ; done

clean:
	@for x in *.a ; do if [ -f "$$x" ] ; then rm $$x ; fi ; done
	@for d in $(SUBDIRS) ; do if [ -d "$$d" ] ; then cd $$d ; make clean ; cd .. ; fi ; done
