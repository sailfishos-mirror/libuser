SUBDIRS = po docs lib apps samples python modules
EXTRA_DIST = libuser.spec libuser-selinux.patch
sysconf_DATA = libuser.conf
pkgconfigdir = $(libdir)/pkgconfig

VERSION=$(shell awk '/Version:/ { print $$2 }' libuser.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' libuser.spec)
CVSTAG=libuser-$(subst .,-,$(VERSION))-$(subst .,-,$(RELEASE))

scan:
	find $(top_srcdir)/include $(top_srcdir)/lib $(top_srcdir)/modules $(top_srcdir)/python $(top_srcdir)/quota -name "*.c" -o -name "*.h" | xargs gtkdoc-scan --module=$(PACKAGE)

force-tag:
	cvs tag -cFR $(CVSTAG) .

tag:
	./autogen.sh
	cvs tag -cR $(CVSTAG) .

archive:
	rm -fr /tmp/$(PACKAGE)-export-tmp
	CVSROOT=`cat CVS/Root`; cd /tmp; cvs -d $$CVSROOT export -r $(CVSTAG) -d $(PACKAGE)-export-tmp $(PACKAGE)
	cd /tmp/$(PACKAGE)-export-tmp; ./autogen.sh --without-sasl --without-ldap; make dist
	mv /tmp/$(PACKAGE)-export-tmp/$(PACKAGE)-$(VERSION).tar.gz .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	@echo Package is in \"$(PACKAGE)-$(VERSION).tar.gz\".

pkgconfig_DATA = $(PACKAGE).pc

ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc \
	--with-python-version=$(PYTHON_VERSION)
