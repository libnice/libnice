
# ccache breaks -fprofile-arcs
export CCACHE_DISABLE=1

OUT=lcov

lcov-clean:
	$(MAKE) clean
	find -name "*.gcno" -o -name "*.gcda" -exec rm '{}' ';'
	rm -rf $(OUT)

lcov-build:
	$(MAKE) CFLAGS="-O0 -fprofile-arcs -ftest-coverage" LDFLAGS="-lgcov" check

lcov-report:
	# hack: move gcov file from libraries back to source directory
	for dir in `find -name .libs`; do \
		(cd `dirname $$dir`; mv .libs/*.gc?? . || true) 2>/dev/null; \
	done

	mkdir -p $(OUT)
	lcov -d . -c >$(OUT)/lcov.info 2>/dev/null
	lcov -l $(OUT)/lcov.info 2>/dev/null |\
		egrep '(^/usr|/test.*\.c)' |\
		cut -d: -f1 >$(OUT)/lcov.remove
	lcov -r $(OUT)/lcov.info `cat $(OUT)/lcov.remove` 2>/dev/null >$(OUT)/lcov.info.clean
	genhtml -o lcov $(OUT)/lcov.info.clean

