## Process this file with automake to produce Makefile.in

## Settings
pkgconfigdir = $(libdir)/pkgconfig

ACLOCAL_AMFLAGS = -I m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --with-ldap \
	--with-python-version=$(PYTHON_VERSION)

CVSTAG = libuser-$(subst .,_,$(VERSION))

## Targets
SUBDIRS = po docs lib apps samples python modules
TESTS = tests/ldap_test

EXTRA_DIST = \
	$(TESTS) tests/ldap.conf.in tests/ldaprc tests/ldap_skel.ldif \
	tests/ldap_test.py tests/slapd.conf.in

pkgconfig_DATA = $(PACKAGE).pc
sysconf_DATA = libuser.conf

## Rules
force-tag:
	cd $(top_srcdir); cvs tag -cFR $(CVSTAG) .

tag:
	cd $(top_srcdir); cvs tag -cR $(CVSTAG) .

archive:
	rm -fr /tmp/$(PACKAGE)-export-tmp
	CVSROOT=`cat $(top_srcdir)/CVS/Root`; cd /tmp; cvs -d $$CVSROOT export -r $(CVSTAG) -d $(PACKAGE)-export-tmp $(PACKAGE)
	cd /tmp/$(PACKAGE)-export-tmp; ./autogen.sh --without-sasl; make dist
	mv /tmp/$(PACKAGE)-export-tmp/$(PACKAGE)-$(VERSION).tar.gz .
	rm -fr /tmp/$(PACKAGE)-export-tmp
	@echo Package is in \"$(PACKAGE)-$(VERSION).tar.gz\".
