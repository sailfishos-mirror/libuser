include $(top_srcdir)/Makefile.extra

pythondir = $(libdir)/python1.5/site-packages/

python_PROGRAMS = libusermodule.so
noinst_SCRIPTS = $(srcdir)/test-script

libusermodule_so_SOURCES = libusermodule.c
libusermodule_so_LDFLAGS = -module -shared $(GLIB_LIBS)
libusermodule_so_LDADD = ../lib/libuser.la
