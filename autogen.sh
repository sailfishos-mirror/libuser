#!/bin/sh
WARNINGS="-Wall -Wimplicit -Wcast-align -Wpointer-arith -Wimplicit-prototypes -Wmissing-prototypes"
#DEFINES="-D_GNU_SOURCE"
set -x
CFLAGS="-g $WARNINGS $DEFINES $CFLAGS" ; export CFLAGS
libtoolize --force
aclocal
automake -a
autoheader
autoconf
test -d intl || gettextize -f -c
rm -f config.cache
./configure --prefix=/usr --sysconfdir=/etc --with-ldap $@
