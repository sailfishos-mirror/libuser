CFLAGS = @CFLAGS@ @GOBJECT_CFLAGS@
LDFLAGS = -no-install

noinst_PROGRAMS = enum field homedir lookup prompt @QUOTASAMPLE@ testuser
EXTRA_PROGRAMS = quotaq
EXTRA_DIST = genusers

enum_SOURCES = enum.c

enum_LDADD = ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

field_SOURCES = field.c

field_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

homedir_SOURCES = homedir.c

homedir_LDADD =  ../apps/apputil.o ../lib/libuser.la @GOBJECT_LIBS@ @PAM_MISC_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

lookup_SOURCES = lookup.c

lookup_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

quotaq_SOURCES = quotaq.c

quotaq_LDADD =  ../lib/libuserquota.la @CRYPT_LIBS@ @INTLLIBS@

prompt_SOURCES = prompt.c

prompt_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@

testuser_SOURCES = testuser.c

testuser_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@ @INTLLIBS@
