include $(top_srcdir)/Makefile.extra

pythondir = $(libdir)/python1.5/site-packages/

python_PROGRAMS = libusermodule.so quotamodule.so
noinst_SCRIPTS = $(srcdir)/test-script $(srcdir)/quota-script

libusermodule_so_SOURCES = libusermodule.c common.h debug.h admin.c ent.c misc.c
libusermodule_so_LDFLAGS = -module -shared $(GLIB_LIBS)
libusermodule_so_LDADD = ../lib/libuser.la

quotamodule_so_SOURCES = quotamodule.c debug.h
quotamodule_so_LDFLAGS = -module -shared $(GLIB_LIBS)
quotamodule_so_LDADD = ../quota/libuser_quota.la
