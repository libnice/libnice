#!/bin/sh

set -e
export G_SLICE=always-malloc

report=`valgrind \
	-q \
	--leak-check=full \
	--show-reachable=no \
	--error-exitcode=1 \
	$1 2>&1`

if echo "$report" | grep -q ==; then
	echo "$report"
	exit 1
fi
