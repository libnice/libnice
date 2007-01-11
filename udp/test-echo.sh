#!/bin/sh
./udp-echo-server &
server_pid=$!
output=`echo foo | ./udp-client`
kill $server_pid
test "$output" = foo || exit 1
exit 0
