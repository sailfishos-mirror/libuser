SUBDIRS = po docs lib apps samples python modules
EXTRA_DIST = libuser.spec libuser.conf.in docs/attributes.txt docs/rfc2307.txt docs/sgml/Makefile docs/sgml/libuser.sgml po/Makefile python/ldap-script python/test-script python/quota-script python/modules.txt docs/reference/libuser.args docs/reference/libuser.hierarchy docs/reference/libuser.signals docs/reference/libuser.types
sysconf_DATA = libuser.conf
pkgconfigdir = $(libdir)/pkgconfig

VERSION=$(shell awk '/Version:/ { print $$2 }' libuser.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' libuser.spec)
CVSTAG=libuser-$(subst .,-,$(VERSION))-$(subst .,-,$(RELEASE))

scan:
	find $(top_srcdir)/include $(top_srcdir)/lib $(top_srcdir)/modules $(top_srcdir)/python $(top_srcdir)/quota -name "*.c" -o -name "*.h" | xargs gtkdoc-scan --module=$(PACKAGE)

tag:
	./autogen.sh
	cvs tag -cFR $(CVSTAG) .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	CVSROOT=`cat CVS/Root`; cd /tmp; cvs -d $$CVSROOT export -r $(CVSTAG) -d $(PACKAGE)-export-tmp $(PACKAGE)
	cd /tmp/$(PACKAGE)-export-tmp; ./autogen.sh --without-sasl --without-ldap; make dist
	mv /tmp/$(PACKAGE)-export-tmp/$(PACKAGE)-$(VERSION).tar.gz .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	@echo Package is in \"$(PACKAGE)-$(VERSION).tar.gz\".

pkgconfig_DATA = $(PACKAGE).pc

ACLOCAL_AMFLAGS = -I m4
