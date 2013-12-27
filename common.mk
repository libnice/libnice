CLEANFILES = *.gcno *.gcda

pkgincludedir = $(includedir)/nice


check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $$(cd "$(top_srcdir)" && pwd)/scripts/valgrind.sh" check

.PHONY: check-valgrind
