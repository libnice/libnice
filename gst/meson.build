gst_nice_sources = [
  'gstnicesrc.c',
  'gstnicesink.c',
  'gstnice.c',
]

gst_nice_args = ['-DGST_USE_UNSTABLE_API']

gst_plugins_install_dir = join_paths(get_option('libdir'), 'gstreamer-1.0')

libgstnice = library('gstnice',
  gst_nice_sources,
  c_args : gst_nice_args,
  include_directories: nice_incs,
  dependencies: [nice_deps, gst_dep],
  link_with: libnice,
  install_dir: gst_plugins_install_dir,
  install: true)

# Generate pc files for static plugins if we build static plugins
if get_option('default_library') != 'shared'
  pkg.generate(libgstnice, install_dir: join_paths(gst_plugins_install_dir, 'pkgconfig'))
endif
