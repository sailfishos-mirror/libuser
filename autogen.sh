#!/bin/sh
aclocal && \
libtoolize --force && \
gettextize -f && \
automake -a && \
autoheader && \
autoconf
