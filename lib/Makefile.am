CFLAGS = @CFLAGS@ -I@PYTHON_INC@ @GLIB_CFLAGS@
LIBADD = @GOBJECT_LIBS@ @CRYPT_LIBS@
LDFLAGS = -version-info 1:0:0

EXTRA_DIST = userquota.3

lib_LTLIBRARIES = libuser.la @QUOTALIB@
EXTRA_LTLIBRARIES = libuserquota.la
man3_MANS = userquota.3

pkginclude_HEADERS = \
	config.h \
	entity.h \
	error.h \
	prompt.h \
	user.h \
	user_private.h \
	userquota.h

libuser_la_SOURCES = \
	config.c \
	config.h \
	entity.c \
	entity.h \
	error.c \
	error.h \
	misc.c \
	modules.c \
	modules.h \
	prompt.c \
	prompt.h \
	scache.c \
	user.c \
	user.h \
	user_private.h \
	util.c \
	util.h

libuserquota_la_SOURCES = \
	userquota.h \
	userquota.c
