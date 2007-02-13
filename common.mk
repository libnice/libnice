
ERROR_CFLAGS = \
	-Wall \
	-Werror \
	-Wextra \
	-Wno-missing-field-initializers \
	-Wwrite-strings \
	-Wmissing-prototypes \
	-Wredundant-decls \
	-Wno-unused-parameter

CLEANFILES = *.gcno *.gcda

check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $(abspath $(top_srcdir))/scripts/valgrind.sh" check

