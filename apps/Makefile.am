bin_PROGRAMS = \
	lchfn \
	lchsh
sbin_PROGRAMS = \
	lchage \
	lid \
	lgroupadd \
	lgroupdel \
	lgroupmod \
	lnewusers \
	lpasswd \
	luseradd \
	luserdel \
	lusermod

CFLAGS = @CFLAGS@ -I@PYTHON_INC@ @GOBJECT_CFLAGS@
LDADD = ../lib/libuser.la @GOBJECT_LIBS@ @PAM_MISC_LIBS@ @POPT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

lchsh_SOURCES = \
	apputil.c \
	apputil.h \
	lchsh.c

lchfn_SOURCES = \
	apputil.c \
	apputil.h \
	lchfn.c

lchage_SOURCES = \
	apputil.c \
	apputil.h \
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
	apputil.c \
	apputil.h \
	lpasswd.c

lnewusers_SOURCES = \
	apputil.c \
	apputil.h \
	lnewusers.c
