EXTRA_DIST = modules.txt

AM_CFLAGS = -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@

pythonexecdir = $(libdir)/python@PYTHON_VERSION@/site-packages

pythonexec_LTLIBRARIES = libusermodule.la
if QUOTA
pythonexec_LTLIBRARIES += libuserquotamodule.la
endif
dist_noinst_SCRIPTS = ldap-script test-script quota-script
noinst_HEADERS = admin.c ent.c misc.c

libusermodule_la_SOURCES = libusermodule.c common.h debug.h ../apps/apputil.c
libusermodule_la_LDFLAGS = -module -avoid-version -export-dynamic \
	@GOBJECT_LIBS@ @PAM_MISC_LIBS@ @CRYPT_LIBS@ @SELINUX_LIBS@
libusermodule_la_LIBADD = ../lib/libuser.la

libuserquotamodule_la_SOURCES = quotamodule.c debug.h
libuserquotamodule_la_LDFLAGS = -module -avoid-version -export-dynamic \
	@GLIB_LIBS@ @CRYPT_LIBS@
libuserquotamodule_la_LIBADD = ../lib/libuserquota.la

install-exec-hook:
	rm -f $(DESTDIR)$(pythonexecdir)/libuser*module.{a,la}
# libtool uninstall doesn't work without the .la files
uninstall-local:
	rm -f $(DESTDIR)$(pythonexecdir)/libuser*module.so
