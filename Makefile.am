SUBDIRS = intl include quota lib modules apps samples python po docs
EXTRA_DIST = Makefile.extra libuser.spec libuser.conf.in docs/attributes.txt docs/rfc2307.txt docs/sgml/Makefile docs/sgml/libuser.sgml po/Makefile python/ldap-script python/test-script python/quota-script python/modules.txt libuser.g
sysconf_DATA = libuser.conf

dist-hook:
	make -f Makefile.in -C po Makefile

doc:
	doxygen libuser.g

VERSION=$(shell awk '/Version:/ { print $$2 }' libuser.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' libuser.spec)
CVSTAG=libuser-$(subst .,-,$(VERSION))-$(subst .,-,$(RELEASE))

scan:
	find $(top_srcdir)/include $(top_srcdir)/lib $(top_srcdir)/modules $(top_srcdir)/python $(top_srcdir)/quota -name "*.c" -o -name "*.h" | xargs gtkdoc-scan --module=$(PACKAGE)

tag:
	cvs tag -cFR $(CVSTAG) .
	CVSROOT=`cat CVS/Root`; cd /tmp; cvs -d $$CVSROOT export -r $(CVSTAG) -d $(PACKAGE)-export-tmp $(PACKAGE)
	rm -fr $(PACKAGE)-$(VERSION)
	mv /tmp/$(PACKAGE)-export-tmp $(PACKAGE)-$(VERSION)-tmp
	cd $(PACKAGE)-$(VERSION); ./autogen.sh; make distcheck
	mv $(PACKAGE)-$(VERSION)-tmp/$(PACKAGE)-$(VERSION).tar.gz
	rm -fr $(PACKAGE)-$(VERSION)-tmp
