# This looks more-or-less correct. <shrug>

pkglib_PROGRAMS = files.so shadow.so krb5.so ldap.so
noinst_PROGRAMS = nis.so

include $(top_srcdir)/Makefile.extra

LDFLAGS = @GLIB_LIBS@ -shared -module -export-dynamic --avoid-version

files_so_SOURCES = \
	files.c \
	util.c \
	util.h

shadow_so_SOURCES = \
	files.c \
	util.c \
	util.h

krb5_so_SOURCES = \
	krb5.c

krb5_so_LDADD = \
	@KRB5_LIBS@

ldap_so_SOURCES = \
	ldap.c

ldap_so_LDADD = \
	@LDAP_LIBS@

nis_so_SOURCES = \
	nis.c

nis_so_LDADD = \
	@NIS_LIBS@
