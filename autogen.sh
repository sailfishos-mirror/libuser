#!/bin/sh
set -x -e
[ -d admin ] || mkdir admin
gtkdocize --docdir docs/reference
libtoolize --force
autopoint
aclocal -I m4
autoconf -Wall
autoheader -Wall
automake -Wall --add-missing
# ./configure --with-ldap --with-sasl --enable-gtk-doc --enable-Werror --with-selinux
