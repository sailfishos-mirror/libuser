noinst_PROGRAMS = enum field lookup prompt quotaq testuser

include $(top_srcdir)/Makefile.extra

enum_SOURCES = \
	enum.c

enum_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

field_SOURCES = \
	field.c

field_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

lookup_SOURCES = \
	lookup.c

lookup_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

quotaq_SOURCES = \
	quotaq.c

quotaq_LDADD = ../quota/libuser_quota.la @INTLLIBS@

prompt_SOURCES = \
	prompt.c

prompt_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

testuser_SOURCES = \
	testuser.c

testuser_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@
