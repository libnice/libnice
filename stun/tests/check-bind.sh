#! /bin/sh

LOG=test-bind.log
rm -f "$LOG"

# Start the STUN test daemon if needed
../stund -4 &
../stund -6 &

# Run the test client
{
	./test-bind
	echo "test-bind returned $?"
} | tee "$LOG"

# Terminate the test daemon
kill -INT %1
kill -INT %2

if ! grep "test-bind returned 0" "$LOG"; then
	echo "test-bind failed" >&2
	exit 1
fi

for a in 127.0.0.1 ::1; do
	for t in Auto UDP; do
		if ! grep -e "^$t discovery *: $a port " "$LOG"; then
			echo "Unexpected mapping from test-bind" >&2
			exit 1
		fi
	done
done

rm -f "$LOG"
exit 0
