AM_CFLAGS = -I../include -I@PYTHON_INC@ @GOBJECT_CFLAGS@ -D_LIBUSER_MODULE

EXTRA_LTLIBRARIES = \
	libuser_files.la \
	libuser_shadow.la \
	libuser_krb5.la \
	libuser_ldap.la \
	libuser_sasldb.la

pkginclude_HEADERS = default.-c
pkglib_LTLIBRARIES = $(MODULES:.so=.la)

AM_LDFLAGS = -module -avoid-version -export-dynamic -rpath '$(pkglibdir)' \
	@GOBJECT_LIBS@ ../lib/libuser.la @SELINUX_LIBS@

libuser_files_la_SOURCES = files.c
libuser_shadow_la_SOURCES = files.c
libuser_krb5_la_SOURCES = krb5.c
libuser_krb5_la_LIBADD = ../lib/libuser.la
libuser_krb5_la_LDFLAGS = @KRB5_LDADD@ @KRB5_LIBS@ @GOBJECT_LIBS
libuser_ldap_la_SOURCES = ldap.c
libuser_ldap_la_LIBADD = ../lib/libuser.la
libuser_ldap_la_LDFLAGS = @LDAP_LDADD@ @LDAP_LIBS@ @GOBJECT_LIBS@
libuser_sasldb_la_SOURCES = sasldb.c
libuser_sasldb_la_LIBADD = ../lib/libuser.la
libuser_sasldb_la_LDFLAGS = @SASL_LDADD@ @SASL_LIBS@ @GOBJECT_LIBS@

install-exec-hook:
	for i in $(MODULES); do \
		rm -f $(DESTDIR)$(pkglibdir)/$${i%.so}.{a,la} ; \
	done
# libtool uninstall doesn't work without the .la files
uninstall-local:
	for i in $(MODULES); do \
		rm -f $(DESTDIR)$(pkglibdir)/$$i ; \
	done
