#!/bin/sh
WARNINGS="-Wall -Wimplicit -Wcast-align -Wpointer-arith -Wpointer-arith -Wmissing-prototypes"
set -x
CFLAGS="-g3 $WARNINGS" ; export CFLAGS
aclocal
libtoolize --force
automake -a
autoheader
autoconf
test -d intl || gettextize -f
./configure --prefix=/usr --exec-prefix=/usr --sysconfdir=/etc $@
