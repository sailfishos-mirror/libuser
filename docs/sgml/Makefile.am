all: libuser.txt libuser.html

libuser.txt: libuser.sgml
	sgml2txt $(srcdir)/libuser.sgml

libuser.html: libuser.sgml
	sgml2html $(srcdir)/libuser.sgml

distclean-local clean-local:
	$(RM) *.html *.txt
