CFLAGS = -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@
LDADD = ../lib/libuser.la

EXTRA_PROGRAMS = \
	libuser_files.so \
	libuser_shadow.so \
	libuser_krb5.so \
	libuser_ldap.so \
	libuser_sasldb.so

pkglib_PROGRAMS = $(MODULES)

LDFLAGS = -shared

libuser_files_so_SOURCES = files.c
libuser_shadow_so_SOURCES = files.c
libuser_krb5_so_SOURCES = krb5.c
libuser_krb5_so_LDADD = @KRB5_LDADD@ @KRB5_LIBS@ ../lib/libuser.la
libuser_ldap_so_SOURCES = ldap.c
libuser_ldap_so_LDADD = @LDAP_LDADD@ @LDAP_LIBS@ ../lib/libuser.la
libuser_sasldb_so_SOURCES = sasldb.c
libuser_sasldb_so_LDADD = @SASL_LDADD@ @SASL_LIBS@ ../lib/libuser.la
