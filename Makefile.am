SUBDIRS = intl include quota lib modules python samples apps po docs
EXTRA_DIST = Makefile.extra libuser.spec libuser.conf.in docs/attributes.txt docs/rfc2307.txt docs/sgml/Makefile docs/sgml/libuser.sgml po/Makefile python/ldap-script python/test-script python/quota-script python/modules.txt libuser.g
sysconf_DATA = libuser.conf

dist-hook:
	make -f Makefile.in -C po Makefile

doc:
	doxygen libuser.g

scan:
	find $(top_srcdir)/include $(top_srcdir)/lib $(top_srcdir)/modules $(top_srcdir)/python $(top_srcdir)/quota -name "*.c" -o -name "*.h" | xargs gtkdoc-scan --module=$(PACKAGE)
