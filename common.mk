CLEANFILES = *.gcno *.gcda

pkgincludedir = $(includedir)/nice


check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="USE_VALGRIND=1 " check

LOG_DRIVER=$(top_srcdir)/scripts/valgrind-test-driver

.PHONY: check-valgrind
