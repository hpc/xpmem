#!/bin/sh

if (libtoolize --version) < /dev/null > /dev/null 2>&1; then
  LIBTOOLIZE=libtoolize
else
  echo "libtoolize was not found! Please install libtool." 1>&2
  exit 1
fi

$LIBTOOLIZE --copy --force || exit 1
aclocal || exit 1
autoheader || exit 1
autoconf || exit 1
automake -a -c || exit 1
