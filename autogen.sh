#!/bin/sh
WARNINGS="-Wall -Wimplicit -Wcast-align -Wpointer-arith -Wpointer-arith -Wmissing-prototypes"
set -x
CFLAGS="-g3 $WARNINGS $CFLAGS" ; export CFLAGS
libtoolize --force
aclocal
automake -a
autoheader
autoconf
test -d intl || gettextize -f -c
./configure --prefix=/usr --exec-prefix=/usr --sysconfdir=/etc $@
