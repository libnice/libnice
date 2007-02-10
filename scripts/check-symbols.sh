#!/bin/sh

usage()
{
	echo "usage: $0 library symbol-file"
	exit 1
}

test -n "$1" || usage
lib="$1"
test -n "$2" || usage
symbol_file="$2"

make_symbol_list=`dirname $0`/make-symbol-list.sh
test -f "$make_symbol_list" || exit 1

if ! test -f "$symbol_file"; then
	echo "$symbol_file doesn't exist"
	exit 1
fi

diff=`sh $make_symbol_list "$lib" | \
	diff -uB "$symbol_file" - | tail -n +3`

# stop if there are no differences
test -z "$diff" && exit 0

echo "symbols for $lib changed"

if echo "$diff" | grep -q '^-'; then
	echo "  missing:"
	echo "$diff" | grep '^-' | cut -b 2- | \
		xargs -i echo "   " "{}"
fi

if echo "$diff" | grep -q '^+'; then
	echo "  extra:"
	echo "$diff" | grep '^+' | cut -b 2- | \
		xargs -i echo "   " "{}"
fi

exit 1

