include $(top_srcdir)/Makefile.extra

EXTRA_PROGRAMS = libuser_files.so libuser_shadow.so libuser_krb5.so libuser_ldap.so
pkglib_PROGRAMS = $(MODULES)

libuser_files_so_SOURCES = files.c
libuser_shadow_so_SOURCES = files.c
libuser_krb5_so_SOURCES = krb5.c
libuser_ldap_so_SOURCES = ldap.c

LDFLAGS = @GLIB_LIBS@ -shared -module -export-dynamic --avoid-version
