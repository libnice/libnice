
SUBDIRS = local stun tests udp random agent nice

EXTRA_DIST = scripts

check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh `pwd`/scripts/valgrind.sh" check

