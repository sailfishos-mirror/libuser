lib_LTLIBRARIES = libuser.la

include $(top_srcdir)/Makefile.extra

libuser_la_LIBADD = @GLIB_LIBS@
LDFLAGS = -version-info 1:0:0
libuser_la_SOURCES = \
	user.c \
	usercfg.c \
	userent.c \
	usererr.c \
	userprmt.c \
	usersc.c \
	userutil.c
