pkglib_LTLIBRARIES = libuser_files.la libuser_shadow.la libuser_krb5.la
EXTRA_LTLIBRARIES = libuser_ldap.la libuser_nis.la

include $(top_srcdir)/Makefile.extra

LDADD = @GLIB_LIBS@

libuser_files_la_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_shadow_la_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_krb5_la_SOURCES = \
	krb5.c

libuser_krb5_la_LIBADD = \
	@KRB5_LIBS@

libuser_ldap_la_SOURCES = \
	ldap.c

libuser_ldap_la_LIBADD = \
	@LDAP_LIBS@

libuser_nis_la_SOURCES = \
	nis.c

libuser_nis_la_LIBADD = \
	@NIS_LIBS@
