EXTRA_DIST = admin.c ent.c misc.c

CFLAGS = -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@

pythondir = $(libdir)/python@PYTHON_VERSION@/site-packages/

python_PROGRAMS = libusermodule.so quotamodule.so
noinst_SCRIPTS = $(srcdir)/test-script $(srcdir)/quota-script

libusermodule_so_SOURCES = libusermodule.c common.h debug.h
libusermodule_so_LDFLAGS = -module -shared @GOBJECT_LIBS@ @PAM_LIBS@ @CRYPT_LIBS@
libusermodule_so_LDADD = ../apps/apputil.o ../lib/libuser.la

quotamodule_so_SOURCES = quotamodule.c debug.h
quotamodule_so_LDFLAGS = -module -shared @GLIB_LIBS@ @CRYPT_LIBS@
quotamodule_so_LDADD = ../quota/libuser_quota.la
