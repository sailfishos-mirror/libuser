#!/bin/sh
set -x -e
mkdir -p admin m4
gtkdocize --docdir docs/reference
libtoolize --force
autopoint -f
aclocal -Wall -I m4
autoconf -Wall
autoheader -Wall
automake -Wall --add-missing
# ./configure --with-ldap --with-sasl --enable-gtk-doc --enable-Werror --with-selinux
