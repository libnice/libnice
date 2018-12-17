examples = ['simple-example', 'threaded-example', 'sdp-example']

foreach ex : examples
  executable(ex, '@0@.c'.format(ex),
    include_directories: nice_incs,
    dependencies: gio_deps + [libnice_dep, gupnp_igd_dep],
    install: false)
endforeach
