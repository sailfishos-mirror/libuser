SUBDIRS = reference

EXTRA_DIST = attributes.txt rfc2307.txt \
	sgml/libuser.sgml

all: sgml/libuser.txt sgml/libuser.html

sgml/libuser.txt: $(srcdir)/sgml/libuser.sgml
	[ -d sgml ] || mkdir sgml
	cd sgml; sgml2txt ../$(srcdir)/sgml/libuser.sgml

sgml/libuser.html: $(srcdir)/sgml/libuser.sgml
	[ -d sgml ] || mkdir sgml
	cd sgml; sgml2html ../$(srcdir)/sgml/libuser.sgml

clean-local:
	rm sgml/*.html sgml/*.txt
