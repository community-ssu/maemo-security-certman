SUBDIRS=cli launcher

all:
	@for d in $(SUBDIRS) ; do if [ -d $$d ] ; then cd $$d ; make ; cd .. ; fi ; done

clean:
	@for d in $(SUBDIRS) ; do if [ -d $$d ] ; then cd $$d ; make clean ; cd .. ; fi ; done
