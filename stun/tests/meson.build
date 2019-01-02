foreach t : ['parse', 'format', 'bind', 'conncheck', 'hmac']
  test_name = 'test-@0@'.format(t)
  exe = executable(test_name, test_name + '.c',
    include_directories: nice_incs,
    dependencies: [syslibs, crypto_dep],
    link_with: libstun)
  test(test_name, exe)
endforeach

# XXX: This test is broken and unused since 2007, ocrete knows about it
# If we enable it, we may want to put it in a separate suite that's only run on
# dist because it takes a long time to run since it tests stun timeouts.
if false and find_program('sh', required : false).found()
  test('test-check-bind', find_program('check-bind.sh'),
    timeout: 600,
    env: 'BUILT_WITH_MESON=1',
    args: [stunbdc_exe, stund_exe])
endif
