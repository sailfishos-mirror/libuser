#!/bin/sh
if test -x /bin/rpm ; then
	if test x${RPM_OPT_FLAGS} = x ; then
		RPM_OPT_FLAGS=`rpm --eval '%optflags'`
	fi
fi
set -x
CFLAGS="$DEFINES $RPM_OPT_FLAGS -O0 -g3 $CFLAGS" ; export CFLAGS
libtoolize --force
cp ChangeLog ChangeLog.old
gettextize -f -c --intl
cat ChangeLog.old > ChangeLog
aclocal -I ./m4
automake -a
autoheader
autoconf
test -f config.cache && rm -f config.cache || true
./configure --prefix=/usr --sysconfdir=/etc --enable-maintainer-mode --with-ldap --with-sasl $@
