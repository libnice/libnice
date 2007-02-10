
ERROR_CFLAGS = \
	-Wall \
	-Werror \
	-Wextra \
	-Wno-missing-field-initializers \
	-Wwrite-strings \
	-Wmissing-prototypes \
	-Wredundant-decls

check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $(abspath $(top_srcdir))/scripts/valgrind.sh" check

