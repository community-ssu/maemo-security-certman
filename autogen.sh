#!/bin/sh

set -x

# glib-gettextize -c -f && \
	libtoolize --force --copy && \
	aclocal && \
	autoheader && \
	automake -ac && \
	autoconf

