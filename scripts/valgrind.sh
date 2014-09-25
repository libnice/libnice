#!/bin/sh

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly

tests_dir="`dirname $0`/../tests"

report=`libtool --mode=execute valgrind \
	--leak-check=full \
	--show-reachable=no \
	--error-exitcode=1 \
	--suppressions=$tests_dir/libnice.supp \
	--num-callers=30 \
	$1 2>&1`

#if echo "$report" | grep -q ==; then
if test $? != 0; then
	echo "$report"
	exit 1
fi

if echo "$report" | grep -q "definitely lost"; then
	if ! echo "$report" | grep -q "definitely lost: 0 bytes"; then
		echo "$report"
		exit 1
	fi
fi

