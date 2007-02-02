
check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $(abspath $(top_srcdir))/scripts/valgrind.sh" check

