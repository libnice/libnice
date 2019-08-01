project('libnice', 'c',
  version: '0.1.16.1',
  meson_version : '>= 0.49.1',
  default_options : ['warning_level=1', 'buildtype=debugoptimized'])

nice_version = meson.project_version()
version_arr = nice_version.split('.')
version_major = version_arr[0]
version_minor = version_arr[1]
version_micro = version_arr[2]
if version_arr.length() == 4
  version_nano = version_arr[3]
else
  version_nano = 0
endif

# maintain compatibility with the previous libtool versioning
soversion = 10
libversion = '10.9.0'

glib_req = '>= 2.54'
gnutls_req = '>= 2.12.0'
gupnp_igd_req = '>= 0.2.4'
gst_req = '>= 1.0.0'

nice_datadir = join_paths(get_option('prefix'), get_option('datadir'))

cc = meson.get_compiler('c')

syslibs = []

if cc.get_id() == 'msvc'
  add_project_arguments(
      cc.get_supported_arguments(['/utf-8']), # set the input encoding to utf-8
      language : 'c')
endif

if host_machine.system() == 'windows'
  syslibs += [cc.find_library('iphlpapi')]
  syslibs += [cc.find_library('ws2_32')]
elif host_machine.system() == 'sunos'
  add_project_arguments('-D_XOPEN_SOURCE=600', language: 'c')
  add_project_arguments('-D__EXTENSIONS__=1', language: 'c')
  # inet_pton() is only used by the tests
  syslibs += [cc.find_library('nsl')]
  if not cc.has_function('inet_pton')
    libnsl = cc.find_library('nsl', required: false)
    if libnsl.found() and cc.has_function('inet_pton', dependencies: libnsl)
      syslibs += [libnsl]
    endif
  endif
  if not cc.has_function('socket')
    libsocket = cc.find_library('socket', required: false)
    libinet = cc.find_library('inet', required: false)
    if cc.has_function('socket', dependencies: libsocket)
      syslibs += [libsocket]
    elif cc.has_function('socket', dependencies: libinet)
      syslibs += [libinet]
    else
      error('Could not find right library for socket() on Solaris')
    endif
  endif
endif

if not cc.has_function('clock_gettime')
  librt = cc.find_library('rt', required: false)
  if cc.has_function('clock_gettime', dependencies: librt)
    syslibs += [librt]
  endif
endif

glib_req_minmax_str = glib_req.split().get(1).underscorify()
add_project_arguments('-D_GNU_SOURCE',
  '-DHAVE_CONFIG_H',
  '-DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_' + glib_req_minmax_str,
  '-DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_' + glib_req_minmax_str,
  language: 'c')

cdata = configuration_data()

cdata.set_quoted('PACKAGE_STRING', meson.project_name())
cdata.set_quoted('PACKAGE_NAME', meson.project_name())
cdata.set_quoted('PACKAGE', meson.project_name())
cdata.set_quoted('VERSION', meson.project_version())

cdata.set('NICEAPI_EXPORT', true,
  description: 'Public library function implementation')

# headers
foreach h : ['arpa/inet.h', 'net/in.h', 'netdb.h', 'ifaddrs.h', 'unistd.h']
  if cc.has_header(h)
    define = 'HAVE_' + h.underscorify().to_upper()
    cdata.set(define, 1)
  endif
endforeach

# functions
foreach f : ['poll', 'getifaddrs']
  if cc.has_function(f)
    define = 'HAVE_' + f.underscorify().to_upper()
    cdata.set(define, 1)
  endif
endforeach

if cc.has_argument('-fno-strict-aliasing')
  add_project_arguments('-fno-strict-aliasing', language: 'c')
endif

# Extra compiler warnings (FIXME: not sure this makes sense to keep like this)
warning_level = get_option('warning_level').to_int()
werror = get_option('werror')

warnings = []

message('warning level: @0@'.format(warning_level))
message('werror enabled: @0@'.format(werror))

if warning_level >= 2
  warnings += [
    '-Wextra',
    '-Wundef',
    '-Wnested-externs',
    '-Wwrite-strings',
    '-Wpointer-arith',
    '-Wmissing-declarations',
    '-Wmissing-prototypes',
    '-Wstrict-prototypes',
    '-Wredundant-decls',
    '-Wno-unused-parameter',
    '-Wno-missing-field-initializers',
    '-Wdeclaration-after-statement',
    '-Wformat=2',
    '-Wold-style-definition',
    '-Wcast-align',
    '-Wformat-nonliteral',
    '-Wformat-security',
  ]
endif
if warning_level >= 3
  warnings += [
    '-Wsign-compare',
    '-Wstrict-aliasing',
    '-Wshadow',
    '-Winline',
    '-Wpacked',
    '-Wmissing-format-attribute',
    '-Winit-self',
    '-Wredundant-decls',
    '-Wmissing-include-dirs',
    '-Wunused-but-set-variable',
    '-Warray-bounds',
  ]
  warnings += [
    '-Wswitch-default',
    '-Waggregate-return',
  ]
endif
if werror
  warnings += [
    '-Wno-suggest-attribute=format',
    '-Wno-cast-function-type',
  ]
endif

foreach w : warnings
  if cc.has_argument(w)
    add_project_arguments(w, language: 'c')
  endif
endforeach

# Dependencies
gio_dep = dependency('gio-2.0', version: glib_req,
  fallback: ['glib', 'libgio_dep'])
gio_deps = [gio_dep]
if gio_dep.type_name() == 'internal'
  # A workaround for libgio_dep not having its dependencies correctly declared.
  # Should be fixed in GLib 2.60.
  gio_deps += [
    dependency('', fallback: ['glib', 'libglib_dep']),
    dependency('', fallback: ['glib', 'libgmodule_dep']),
    dependency('', fallback: ['glib', 'libgobject_dep'])
  ]
endif
gthread_dep = dependency('gthread-2.0',
  fallback: ['glib', 'libgthread_dep'])

# Cryto library
opt_cryptolib = get_option('crypto-library')
message('Crypto librar requested: ' + opt_cryptolib)
if opt_cryptolib != 'openssl'
  crypto_dep = dependency('gnutls', version: gnutls_req, required: false)
  cdata.set('HAVE_GNUTLS', crypto_dep.found())
  if not crypto_dep.found() and opt_cryptolib == 'auto'
    crypto_dep = dependency('openssl', required: false,
      fallback: ['openssl', 'openssl_dep'])
    cdata.set('HAVE_OPENSSL', crypto_dep.found())
  endif
else
  crypto_dep = dependency('openssl', required: false)
  cdata.set('HAVE_OPENSSL', crypto_dep.found())
  if not crypto_dep.found() and openssl == 'auto'
    crypto_dep = dependency('gnutls', version: gnutls_req, required: false)
    cdata.set('HAVE_GNUTLS', crypto_dep.found())
  endif
endif

if not crypto_dep.found() and opt_cryptolib != 'gnutls'
  # MSVC builds of OpenSSL does not generate pkg-config files,
  # so we check for it manually here in this case, if we can't find those files
  # Based on the CMake check for OpenSSL in CURL's CMakeLists.txt,
  # on which headers we should check for
  openssl_headers = []
  foreach h : ['crypto.h', 'engine.h', 'err.h', 'pem.h',
               'rsa.h', 'ssl.h', 'x509.h', 'rand.h', 'tls1.h']
    openssl_headers += 'openssl/' + h
  endforeach

  # OpenSSL 1.1.x and 1.0.x (or earlier) have different .lib names,
  # so we need to look for the correct pair

  # Find either libcrypto.lib (1.1.x) or libeay32.lib (1.0.x or earlier) first
  libcrypto_dep = cc.find_library('crypto', required: false)
  if libcrypto_dep.found()
    libssl = 'ssl'
  else
    libcrypto_dep = cc.find_library('eay32', required: false)
    libssl = 'ssleay32'
  endif

  if libcrypto_dep.found()
    # Find the corresponding SSL library depending on which crypto .lib we found
    libssl_dep = cc.find_library(libssl, required: false, has_headers: openssl_headers)
  endif

  if libcrypto_dep.found() and libssl_dep.found()
    crypto_dep = [libcrypto_dep, libssl_dep]
  endif
endif

if not crypto_dep.found()
  if opt_cryptolib == 'gnutls'
    error('GnuTLS requested as crypto library, but not found')
  elif opt_cryptolib == 'gnutls'
    error('OpenSSL requested as crypto library, but not found')
  else
    error('Either GnuTLS or OpenSSL is required as crypto library, but neither was found')
  endif
endif

# GStreamer
gst_dep = dependency('gstreamer-base-1.0', version: gst_req,
  required: get_option('gstreamer'),
  fallback : ['gstreamer', 'gst_base_dep'])

cdata.set('HAVE_GSTREAMER', gst_dep.found(), description: 'Build GStreamer plugin')

# GUPnP IGD
gupnp_igd_dep = dependency('gupnp-igd-1.0', version: gupnp_igd_req, required: get_option('gupnp'))
cdata.set('HAVE_GUPNP', gupnp_igd_dep.found(), description: 'Use the GUPnP IGD library')

libm = cc.find_library('m', required: false)

nice_incs = include_directories('.', 'agent', 'random', 'socket', 'stun')

nice_deps = gio_deps + [gthread_dep, crypto_dep, gupnp_igd_dep] + syslibs

ignored_iface_prefix = get_option('ignored-network-interface-prefix')
if ignored_iface_prefix != []
  ignored_iface_prefix_quoted = []
  foreach i : ignored_iface_prefix
    ignored_iface_prefix_quoted += '"' + i + '"'
  endforeach
  cdata.set('IGNORED_IFACE_PREFIX', ','.join(ignored_iface_prefix_quoted))
endif

gir = find_program('g-ir-scanner', required : get_option('introspection'))

subdir('agent')
subdir('stun')
subdir('socket')
subdir('random')
subdir('nice')

if gst_dep.found()
  subdir('gst')
endif

if build_machine.system() == 'windows'
  message('Disabling gtk-doc while building on Windows')
else
  if find_program('gtkdoc-scan', required: get_option('gtk_doc')).found()
    subdir('docs/reference/libnice')
  else
    message('Not building documentation as gtk-doc was not found or disabled')
  endif
endif

if not get_option('tests').disabled()
  subdir('tests')
endif

if not get_option('examples').disabled()
  subdir('examples')
endif

add_test_setup('valgrind',
	       exe_wrapper: ['valgrind',
			     '--leak-check=full',
			     '--show-reachable=no',
			     '--error-exitcode=1',
			     '--suppressions='+meson.current_source_dir()+'/tests/libnice.supp',
			     '--num-callers=10'],
	       timeout_multiplier: 10
	      )

configure_file(output : 'config.h', configuration : cdata)
