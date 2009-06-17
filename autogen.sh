#!/bin/sh
set -e

test -d m4 || mkdir m4
gtkdocize || exit 1

autoreconf -fi

run_configure=true
for arg in $*; do
    case $arg in
        --no-configure)
            run_configure=false
            ;;
        *)
            ;;
    esac
done

if test $run_configure = true; then
    ./configure "$@"
fi
