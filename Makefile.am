SUBDIRS = intl include lib quota modules apps samples python po docs
EXTRA_DIST = libuser.spec libuser.conf.in docs/attributes.txt docs/rfc2307.txt docs/sgml/Makefile docs/sgml/libuser.sgml po/Makefile python/ldap-script python/test-script python/quota-script python/modules.txt libuser.g depcomp
sysconf_DATA = libuser.conf
pkgconfigdir = $(libdir)/pkgconfig

dist-hook:
	make -f Makefile.in -C po Makefile

doc:
	doxygen libuser.g 2> doxygen.out

VERSION=$(shell awk '/Version:/ { print $$2 }' libuser.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' libuser.spec)
CVSTAG=libuser-$(subst .,-,$(VERSION))-$(subst .,-,$(RELEASE))

scan:
	find $(top_srcdir)/include $(top_srcdir)/lib $(top_srcdir)/modules $(top_srcdir)/python $(top_srcdir)/quota -name "*.c" -o -name "*.h" | xargs gtkdoc-scan --module=$(PACKAGE)

tag:
	./config.status
	cvs tag -cFR $(CVSTAG) .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	CVSROOT=`cat CVS/Root`; cd /tmp; cvs -d $$CVSROOT export -r $(CVSTAG) -d $(PACKAGE)-export-tmp $(PACKAGE)
	cd /tmp/$(PACKAGE)-export-tmp; ./autogen.sh; make dist
	mv /tmp/$(PACKAGE)-export-tmp/$(PACKAGE)-$(VERSION).tar.gz .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	@echo Package is in \"$(PACKAGE)-$(VERSION).tar.gz\".

pkgconfig_DATA = $(PACKAGE).pc
