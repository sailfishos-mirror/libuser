EXTRA_DIST = modules.txt

AM_CFLAGS = -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@

pythonexecdir = $(libdir)/python@PYTHON_VERSION@/site-packages/

pythonexec_LTLIBRARIES = libusermodule.la $(QUOTAMODULE:.so=.la)
EXTRA_LTLIBRARIES = libuserquotamodule.la
noinst_SCRIPTS = ldap-script test-script quota-script
noinst_HEADERS = admin.c ent.c misc.c

libusermodule_la_SOURCES = libusermodule.c common.h debug.h ../apps/apputil.c
libusermodule_la_LDFLAGS = -module -avoid-version -export-dynamic \
	-rpath '$(pythonexecdir)' @GOBJECT_LIBS@ @PAM_MISC_LIBS@ @CRYPT_LIBS@
libusermodule_la_LIBADD = ../lib/libuser.la

libuserquotamodule_la_SOURCES = quotamodule.c debug.h
libuserquotamodule_la_LDFLAGS = -module -avoid-version -export-dynamic \
	-rpath '$(pythonexecdir)' @GLIB_LIBS@ @CRYPT_LIBS@
libuserquotamodule_la_LIBADD = ../lib/libuserquota.la

install-exec-hook:
	rm -f $(DESTDIR)$(pythonexecdir)/*.{a,la}
