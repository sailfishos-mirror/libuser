noinst_PROGRAMS = enum field homedir lookup prompt quotaq testuser
EXTRA_DIST = genusers

include $(top_srcdir)/Makefile.extra

enum_SOURCES = \
	enum.c

enum_LDADD = ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

field_SOURCES = \
	field.c

field_LDADD =  ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

homedir_SOURCES = \
	homedir.c

homedir_LDADD =  ../apps/apputil.o ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

lookup_SOURCES = \
	lookup.c

lookup_LDADD =  ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

quotaq_SOURCES = \
	quotaq.c

quotaq_LDADD =  ../quota/libuser_quota.la @INTLLIBS@

prompt_SOURCES = \
	prompt.c

prompt_LDADD =  ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@

testuser_SOURCES = \
	testuser.c

testuser_LDADD =  ../lib/libuser.la @GLIB_LIBS@ @INTLLIBS@
