include $(top_srcdir)/Makefile.extra

EXTRA_PROGRAMS = libuser_files.so libuser_shadow.so libuser_krb5.so libuser_ldap.so
pkglib_PROGRAMS = $(MODULES)

libuser_files_so_SOURCES = files.c
libuser_shadow_so_SOURCES = files.c
LDADD = ../lib/libuser.la
libuser_krb5_so_SOURCES = krb5.c
libuser_krb5_so_LDADD = @KRB5_LIBS@ ../lib/libuser.la
libuser_ldap_so_SOURCES = ldap.c
libuser_ldap_so_LDADD = @LDAP_LIBS@ ../lib/libuser.la

LDFLAGS = @GLIB_LIBS@ -shared -module -export-dynamic --avoid-version
