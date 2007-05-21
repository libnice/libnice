#! /bin/sh

STUNC=../stunbdc
STUND=../stund

set -xe

# Dummy command line parsing tests
$STUNC -h
$STUNC -V
! $STUNC server port dummy

# Timeout tests
! $STUNC -4 127.0.0.1 1
! $STUNC -6 ::1 1

# Real tests

# Start the STUN test daemon if needed
rm -f stund-*.err stunc-*.log

exit 77
# FIXME: kill daemons properly
# FIXME: use custom port number

( $STUND -4 || echo ABORT > stund-IPv4.err ) &
( $STUND -6 || echo ABORT > stund-IPv6.err ) &

# Run the test client
$STUNC -4 > stunc-IPv4.log || test -f stund-IPv4.err
$STUNC -6 > stunc-IPv6.log || test -f stund-IPv6.err

# Terminate the test daemon
kill -INT %1 2>/dev/null || true
kill -INT %2 2>/dev/null || true

# Check client results
if test -f stund-IPv4.err; then exit 77; fi
grep -e "^Mapped address: 127.0.0.1" stunc-IPv4.log || exit 4

if test -f stund-IPv6.err; then exit 77; fi
grep -e "^Mapped address: ::1" stunc-IPv6.log || exit 6
