#! /bin/sh

STUND=../stun/tools/stund

echo "Starting ICE full-mode with STUN unit test."

[ -e "$STUND" ] || {
	echo "STUN server not found: Cannot run unit test!" >&2
	exit 77
}

set -x
pidfile=./stund.pid

export NICE_STUN_SERVER=127.0.0.1
export NICE_STUN_SERVER_PORT=3800

echo "Launching stund on port ${NICE_STUN_SERVER_PORT}."

rm -f -- "$pidfile"
(sh -c "echo \$\$ > \"$pidfile\" && exec "$STUND" ${NICE_STUN_SERVER_PORT}") &
sleep 1

./test-fullmode
error=$?

kill "$(cat "$pidfile")"
rm -f -- "$pidfile"
wait
exit ${error}
