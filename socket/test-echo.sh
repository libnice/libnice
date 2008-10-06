#!/bin/sh
set -e
./udp-echo-server &
server_pid=$!
# give server a chance to bind to socket
sleep 1
output=`echo foo | ./udp-client`
kill $server_pid
test "$output" = foo || exit 1
exit 0
