CFLAGS = @CFLAGS@ -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@
LIBADD = @GLIB_LIBS@
LDFLAGS = -version-info 1:0:0

lib_LTLIBRARIES = libuser.la

libuser_la_SOURCES = \
	config.c \
	entity.c \
	error.c \
	misc.c \
	modules.c \
	prompt.c \
	scache.c \
	user.c \
	util.c

libuser_la_LIBADD = @GLIB_LIBS@
