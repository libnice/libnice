#!/bin/sh

set -e

TEST_PSEUDOTCP="$1"

cleanup() {
  rm -rf rand rand-copy
}

trap cleanup EXIT

dd if=/dev/urandom of=rand count=1024 ibs=1024
"${TEST_PSEUDOTCP}" rand rand-copy
diff rand rand-copy
