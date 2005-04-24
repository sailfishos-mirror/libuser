#!/bin/sh
if test -x /bin/rpm ; then
	if test x${RPM_OPT_FLAGS} = x ; then
		RPM_OPT_FLAGS=`rpm --eval '%optflags'`
	fi
fi
set -x -e
CFLAGS="$DEFINES $RPM_OPT_FLAGS -O0 -g3 $CFLAGS" ; export CFLAGS
[ -d admin ] || mkdir admin
gtkdocize --docdir docs/reference
libtoolize --force
autopoint
aclocal -I m4
autoconf -Wall
autoheader -Wall
automake -Wall --add-missing
# ./configure --prefix=/usr --sysconfdir=/etc --with-ldap --with-sasl --enable-gtk-doc
