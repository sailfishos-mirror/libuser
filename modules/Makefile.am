# This looks more-or-less correct. <shrug>

pkglib_PROGRAMS = libuser_files.so libuser_shadow.so libuser_krb5.so libuser_ldap.so
noinst_PROGRAMS = libuser_nis.so

include $(top_srcdir)/Makefile.extra

LDFLAGS = @GLIB_LIBS@ -shared -module -export-dynamic --avoid-version

libuser_files_so_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_shadow_so_SOURCES = \
	files.c \
	util.c \
	util.h

libuser_krb5_so_SOURCES = \
	krb5.c

libuser_krb5_so_LDADD = \
	@KRB5_LIBS@

libuser_ldap_so_SOURCES = \
	ldap.c

libuser_ldap_so_LDADD = \
	@LDAP_LIBS@

libuser_nis_so_SOURCES = \
	nis.c

libuser_nis_so_LDADD = \
	@NIS_LIBS@
