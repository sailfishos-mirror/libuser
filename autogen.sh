#!/bin/sh -x
aclocal
libtoolize --force
automake -a
autoheader
autoconf
gettextize -f
./configure $@
