#!/bin/sh
if test -x /bin/rpm ; then
	if test x${RPM_OPT_FLAGS} = x ; then
		RPM_OPT_FLAGS=`rpm --eval '%optflags'`
	fi
fi
set -x
CFLAGS="$DEFINES $RPM_OPT_FLAGS -O0 -g3 $CFLAGS" ; export CFLAGS
libtoolize --force
aclocal -I ./m4
automake -a
autoheader
autoconf
test -d intl || gettextize -f -c
rm -f config.cache
./configure --prefix=/usr --sysconfdir=/etc --enable-maintainer-mode --with-ldap --with-sasl $@
