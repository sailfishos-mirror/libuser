CFLAGS = @CFLAGS@ -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@
LIBADD = @GLIB_LIBS@ @CRYPT_LIBS@
LDFLAGS = -version-info 1:0:0

lib_LTLIBRARIES = libuser.la

libuser_la_SOURCES = \
	config.c \
	entity.c \
	error.c \
	misc.c \
	misc.h \
	modules.c \
	modules.h \
	prompt.c \
	scache.c \
	user.c \
	util.c \
	util.h

libuser_la_LIBADD = @GLIB_LIBS@
