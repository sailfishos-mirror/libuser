CFLAGS = -I../include -I@PYTHON_INC@ @GLIB_CFLAGS@
LIBADD = @GMODULE_LIBS@

pkginclude_HEADERS = \
	config.h \
	entity.h \
	error.h \
	prompt.h \
	quota.h \
	user.h \
	user_private.h

noinst_PROGRAMS = trivial
trivial_SOURCES = trivial.c
