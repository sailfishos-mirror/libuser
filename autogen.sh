#!/bin/sh
WARNINGS="-Wall -Wimplicit -Wcast-align -Wpointer-arith -Wpointer-arith -Wmissing-prototypes"
#DEFINES="-D_GNU_SOURCE"
set -x
CFLAGS="-g3 $WARNINGS $DEFINES $CFLAGS" ; export CFLAGS
libtoolize --force
aclocal
automake -a
autoheader
autoconf
test -d intl || gettextize -f -c
rm -f config.cache
./configure --prefix=/usr --sysconfdir=/etc --with-ldap --with-krb5=/usr/kerberos --with-sasl $@
