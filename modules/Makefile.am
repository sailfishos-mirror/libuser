pkglib_LTLIBRARIES = libuser_files.la libuser_shadow.la \
		     libuser_krb5.la libuser_ldap.la
EXTRA_LTLIBRARIES = libuser_nis.la

include $(top_srcdir)/Makefile.extra

LDFLAGS = @GLIB_LIBS@

libuser_files_la_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_files_la_LDFLAGS = -version-info 0:1:0

libuser_shadow_la_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_shadow_la_LDFLAGS = -version-info 0:1:0

libuser_krb5_la_SOURCES = \
	krb5.c

libuser_krb5_la_LIBADD = \
	@KRB5_LIBS@

libuser_krb5_la_LDFLAGS = -version-info 0:1:0

libuser_ldap_la_SOURCES = \
	ldap.c

libuser_ldap_la_LIBADD = \
	@LDAP_LIBS@

libuser_ldap_la_LDFLAGS = -version-info 0:0:0

libuser_nis_la_SOURCES = \
	nis.c

libuser_nis_la_LIBADD = \
	@NIS_LIBS@

libuser_nis_la_LDFLAGS = -version-info 0:0:0
