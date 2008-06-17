#! /bin/sh

STUNC=../tools/stunbdc
STUND=../tools/stund

set -xe

# Dummy command line parsing tests
$STUNC -h
$STUNC -V
! $STUNC server port dummy

# Timeout tests
! $STUNC -4 127.0.0.1 1
! $STUNC -6 ::1 1

# Allocate a likely unused port number
PORT=$((32768+$$))
if test $PORT -le 1024; then
	PORT=$(($PORT+1024))
fi

echo "Using local UDP port number $PORT ..."

# Start the STUN test daemon if needed
rm -f stund?.pid stund?.fail stunc?.log

for v in 4 6; do
	(($SHELL -c "echo \$\$ > stund$v.pid ; exec $STUND -$v $PORT") || \
		touch stund$v.fail) &
done

# Run the test client
$STUNC -4 127.0.0.1 $PORT > stunc4.log || test -f stund4.fail
$STUNC -6 ::1 $PORT > stunc6.log || test -f stund6.fail

# Terminate the test daemon
for v in 4 6; do kill -INT $(cat stund$v.pid) || true; done
wait

# Check client results
if test -f stund4.fail; then exit 77; fi
grep -e "^Mapped address: 127.0.0.1" stunc4.log || exit 4

if test -f stund6.fail; then exit 77; fi
grep -e "^Mapped address: ::1" stunc6.log || exit 6

rm -f stund?.fail stund?.pid stunc?.log
