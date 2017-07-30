#!/bin/sh

set -e

if test -n "${BUILT_WITH_MESON}"; then
  TEST_PSEUDOTCP=$1
else
  TEST_PSEUDOTCP=./test-pseudotcp
fi

cleanup() {
  rm -rf rand rand-copy
}

trap cleanup EXIT

dd if=/dev/urandom of=rand count=1024 ibs=1024
"${TEST_PSEUDOTCP}" rand rand-copy
diff rand rand-copy
