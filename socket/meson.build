socket_sources = [
  'socket.c',
  'udp-bsd.c',
  'tcp-bsd.c',
  'tcp-active.c',
  'tcp-passive.c',
  'pseudossl.c',
  'socks5.c',
  'http.c',
  'udp-turn.c',
  'udp-turn-over-tcp.c',
]

libsocket = static_library('socket', socket_sources,
  c_args: ['-DG_LOG_DOMAIN="libnice-socket"'],
  include_directories: nice_incs,
  dependencies: nice_deps,
  install: false)
