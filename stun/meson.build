stun_sources = [
  'stunagent.c',
  'stunmessage.c',
  'stun5389.c',
  'stuncrc32.c',
  'rand.c',
  'stunhmac.c',
  'utils.c',
  'debug.c',
  'usages/ice.c',
  'usages/bind.c',
  'usages/turn.c',
  'usages/timer.c',
]

install_headers(
  'stunagent.h',
  'stunmessage.h',
  'win32_common.h', # installed unconditionally?!
  'debug.h',
  'constants.h', subdir: 'stun')

install_headers(
  'usages/bind.h',
  'usages/ice.h',
  'usages/turn.h',
  'usages/timer.h', subdir: 'stun/usages')

libstun = static_library('stun', stun_sources,
  c_args: ['-DG_LOG_DOMAIN="libnice-stun"'],
  include_directories: nice_incs,
  dependencies: nice_deps,
  install: false)

subdir('tools')

if not get_option('tests').disabled()
  subdir('tests')
endif
