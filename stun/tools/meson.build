stund_exe = executable('stund', 'stund.c',
  include_directories: nice_incs,
  link_with: libstun,
  install: true)

stunbdc_exe = executable('stunbdc', 'stunbdc.c',
  include_directories: nice_incs,
  dependencies: syslibs,
  link_with: libstun,
  install: true)
