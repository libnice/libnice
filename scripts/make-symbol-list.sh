#!/bin/sh
test -n "$1" || exit 1
nm --print-file-name --defined-only --extern-only "$1" | \
	cut -d ' ' -f 2,3 | \
	grep -v '^[rA]' | \
	sort
