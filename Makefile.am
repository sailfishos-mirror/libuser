SUBDIRS = intl include quota lib modules python samples apps po docs
EXTRA_DIST = Makefile.extra libuser.spec libuser.conf.in docs/attributes.txt docs/rfc2307.txt docs/sgml/Makefile docs/sgml/libuser.sgml po/Makefile python/test-script libuser.g
sysconf_DATA = libuser.conf

dist-hook:
	make -f Makefile.in -C po Makefile

doc:
	doxygen libuser.g
