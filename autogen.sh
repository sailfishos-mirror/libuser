#!/bin/sh
aclocal && \
libtoolize --force && \
automake -a && \
autoheader && \
autoconf && \
gettextize -f
