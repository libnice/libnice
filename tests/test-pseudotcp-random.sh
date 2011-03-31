#!/bin/sh

dd if=/dev/urandom of=rand count=1024 ibs=1024
./test-pseudotcp rand rand-copy
diff rand rand-copy
rm -rf rand rand-copy
