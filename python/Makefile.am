EXTRA_DIST = admin.c ent.c misc.c

CFLAGS = @CFLAGS@ -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@

pythondir = $(libdir)/python@PYTHON_VERSION@/site-packages/

python_PROGRAMS = libusermodule.so @QUOTAMODULE@
EXTRA_PROGRAMS = libuserquotamodule.so
noinst_SCRIPTS = $(srcdir)/test-script $(srcdir)/quota-script

libusermodule_so_SOURCES = libusermodule.c common.h debug.h
libusermodule_so_LDFLAGS = -module -shared @GOBJECT_LIBS@ @PAM_MISC_LIBS@ @CRYPT_LIBS@
libusermodule_so_LDADD = ../apps/apputil.o ../lib/libuser.la

libuserquotamodule_so_SOURCES = quotamodule.c debug.h
libuserquotamodule_so_LDFLAGS = -module -shared @GLIB_LIBS@ @CRYPT_LIBS@
libuserquotamodule_so_LDADD = ../lib/libuserquota.la
