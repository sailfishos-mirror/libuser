noinst_PROGRAMS = lookup testuser prompt field enum

include $(top_srcdir)/Makefile.extra

LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

lookup_SOURCES = \
	lookup.c

testuser_SOURCES = \
	testuser.c

prompt_SOURCES = \
	prompt.c

field_SOURCES = \
	field.c

enum_SOURCES = \
	enum.c
