sbin_PROGRAMS = lchage lid luseradd lusermod luserdel lgroupadd lgroupmod lgroupdel lpasswd

include $(top_srcdir)/Makefile.extra

LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

lchage_SOURCES = \
	lchage.c

lid_SOURCES = \
	lid.c

luseradd_SOURCES = \
	apputil.c \
	apputil.h \
	luseradd.c

lusermod_SOURCES = \
	apputil.c \
	apputil.h \
	lusermod.c

luserdel_SOURCES = \
	apputil.c \
	apputil.h \
	luserdel.c

lgroupadd_SOURCES = \
	apputil.c \
	apputil.h \
	lgroupadd.c

lgroupmod_SOURCES = \
	apputil.c \
	apputil.h \
	lgroupmod.c

lgroupdel_SOURCES = \
	apputil.c \
	apputil.h \
	lgroupdel.c

lpasswd_SOURCES = \
	lpasswd.c
