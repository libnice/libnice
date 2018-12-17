librandom = static_library('nice-random',
  'random.c', 'random-glib.c',
  c_args: ['-DG_LOG_DOMAIN="libnice-random"'],
  include_directories: nice_incs,
  dependencies: gio_deps + [gthread_dep],
  install: false)

if not get_option('tests').disabled()
  test_exe = executable('nice-random-test', 'test.c',
    include_directories: nice_incs,
    dependencies: gio_deps + [gthread_dep],
    link_with: librandom)

  test('nice-random', test_exe)
endif
