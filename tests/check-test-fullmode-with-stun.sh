#! /bin/sh

if test -n "${BUILT_WITH_MESON}"; then
  STUND=$1
  TEST_FULLMODE=$2
else
  STUND=../stun/tools/stund
  TEST_FULLMODE=./test-fullmode
fi

echo "Starting ICE full-mode with STUN unit test."

[ -e "$STUND" ] || {
	echo "STUN server not found: Cannot run unit test!" >&2
	exit 77
}

set -x
pidfile=./stund.pid

export NICE_STUN_SERVER=127.0.0.1
export NICE_STUN_SERVER_PORT=3800

echo "Launching $STUND on port ${NICE_STUN_SERVER_PORT}."

rm -f -- "$pidfile"
(sh -c "echo \$\$ > \"$pidfile\" && exec "$STUND" ${NICE_STUN_SERVER_PORT}") &
sleep 1

"${TEST_FULLMODE}"
error=$?

kill "$(cat "$pidfile")"
rm -f -- "$pidfile"
wait
exit ${error}
