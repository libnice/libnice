#!/bin/sh

set -e

if test -z "$srcdir"; then
	srcdir=.
fi

check_symbols=$srcdir/../scripts/check-symbols.sh

if ! test -f $check_symbols; then
	echo "can't find check-symbols.sh"
fi

sh $check_symbols .libs/libnice.so $srcdir/libnice.symbols
