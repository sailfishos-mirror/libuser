CFLAGS = @CFLAGS@ -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@
LIBADD = @GOBJECT_LIBS@ @CRYPT_LIBS@
LDFLAGS = -version-info 1:0:0

lib_LTLIBRARIES = libuser.la libuserquota.la
man3_MANS = userquota.3

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

libuserquota_la_SOURCES = \
	quota.h \
	userquota.c
