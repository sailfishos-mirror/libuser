AM_CFLAGS = @GOBJECT_CFLAGS@
AM_LDFLAGS = -no-install

noinst_PROGRAMS = enum field homedir lookup prompt testuser
if QUOTA
noinst_PROGRAMS += quotaq
endif
EXTRA_DIST = genusers

enum_SOURCES = enum.c

enum_LDADD = ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@

field_SOURCES = field.c

field_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@

homedir_SOURCES = homedir.c

homedir_LDADD =  ../apps/apputil.o ../lib/libuser.la @GOBJECT_LIBS@ @PAM_MISC_LIBS@ @CRYPT_LIBS@

lookup_SOURCES = lookup.c

lookup_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@

quotaq_SOURCES = quotaq.c

quotaq_LDADD =  ../lib/libuserquota.la @CRYPT_LIBS@

prompt_SOURCES = prompt.c

prompt_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@

testuser_SOURCES = testuser.c

testuser_LDADD =  ../lib/libuser.la @GOBJECT_LIBS@ @CRYPT_LIBS@
