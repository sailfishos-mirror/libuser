all: libuser.txt libuser.html

libuser.txt: libuser.sgml
	sgml2txt libuser.sgml

libuser.html: libuser.sgml
	sgml2html libuser.sgml

clean:
	$(RM) *.html *.txt
