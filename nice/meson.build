nice_link_args = []

# libnice.def
libnice_def = custom_target('libnice.def',
    command: [find_program('gen-def.py'), '@INPUT@'],
    input: 'libnice.sym',
    output: 'libnice.def',
    capture: true)

# map file
mapfile = custom_target('libnice.map',
    command: [find_program('gen-map.py'), '@INPUT@'],
    input: 'libnice.sym',
    output: 'libnice.map',
    capture: true)
# We need to check with a file that exists at configure time!
if cc.has_link_argument('-Wl,--version-script,@0@/libnice.ver'.format(meson.current_source_dir()))
  nice_link_args += ['-Wl,--version-script,@0@'.format(mapfile.full_path())]
endif

libnice = library('nice',
  link_whole: [libagent, libsocket, libstun, librandom],
  dependencies: nice_deps,
  # Add agent include to uninstalled pkgconfig file
  include_directories: agent_include,
  version : libversion,
  soversion : soversion,
  vs_module_defs: libnice_def,
  link_args: nice_link_args,
  link_depends: mapfile,
  install: true)

version_conf = configuration_data()
version_conf.set('version_major', version_major)
version_conf.set('version_minor', version_minor)
version_conf.set('version_micro', version_micro)
version_conf.set('version_nano', version_nano)
nice_version_h = configure_file(input : 'nice-version.h.in',
  output: 'nice-version.h',
  install_dir: get_option('includedir') / 'nice',
  configuration: version_conf)

install_headers('nice.h', subdir: 'nice')
nice_include = include_directories('.')

nice_gen_sources = [nice_version_h]

# introspection
build_gir = gir.found() and not get_option('introspection').disabled()
if build_gir
  nice_gen_sources += [
    gnome.generate_gir(libnice,
      sources : [agent_headers, agent_sources],
      namespace : 'Nice',
      nsversion : '0.1',
      identifier_prefix : 'Nice',
      symbol_prefix: 'nice',
      export_packages: 'nice',
      includes: ['GObject-2.0', 'Gio-2.0'],
      extra_args: ['--accept-unprefixed'],
      install: true)
  ]
endif

libnice_dep = declare_dependency(link_with : libnice,
  include_directories : [agent_include, nice_include],
  # Everything that uses libnice needs this built to compile
  sources : nice_gen_sources,
  dependencies: nice_deps)

# pkg-config file
pkg = import('pkgconfig')
upnp_enabled_string = gupnp_igd_dep.found() ? 'true' : 'false'
pkg.generate(libnice,
  name: 'libnice',
  filebase: 'nice',
  subdirs: 'nice',
  description: 'ICE library',
  libraries: gio_dep,
  variables: ['upnp_enabled=@0@'.format(upnp_enabled_string)])
