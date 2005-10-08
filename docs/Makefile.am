SUBDIRS = reference

man_MANS = libuser.conf.5

CLEANFILES = $(man_MANS)
EXTRA_DIST = attributes.txt libuser.conf.5.in rfc2307.txt sgml/libuser.sgml

all: sgml/libuser.txt sgml/libuser.html

libuser.conf.5: $(srcdir)/libuser.conf.5.in Makefile
	sed -e 's,@sysconfdir\@,$(sysconfdir),g' \
		-e 's,@pkglibdir\@,$(pkglibdir),g' \
		< $(srcdir)/libuser.conf.5.in > $@

sgml/libuser.txt: $(srcdir)/sgml/libuser.sgml
	[ -d sgml ] || mkdir sgml
	cd sgml; sgml2txt ../$(srcdir)/sgml/libuser.sgml

sgml/libuser.html: $(srcdir)/sgml/libuser.sgml
	[ -d sgml ] || mkdir sgml
	cd sgml; sgml2html ../$(srcdir)/sgml/libuser.sgml

clean-local:
	rm sgml/*.html sgml/*.txt
