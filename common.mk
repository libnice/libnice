
ERROR_CFLAGS = \
	-Wall \
	-Werror \
	-Wextra \
	-Wno-missing-field-initializers \
	-Wwrite-strings \
	-Wmissing-prototypes \
	-Wredundant-decls

CLEANFILES = *.gcno *.gcda

check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $(abspath $(top_srcdir))/scripts/valgrind.sh" check

