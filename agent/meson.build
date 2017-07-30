agent_headers = files([
  'address.h',
  'agent.h',
  'candidate.h',
  'debug.h',
  'interfaces.h',
  'pseudotcp.h',
])
install_headers(agent_headers, subdir : 'nice')
agent_include = include_directories('.')

agent_sources = files([
  'address.c',
  'agent.c',
  'candidate.c',
  'component.c',
  'conncheck.c',
  'debug.c',
  'discovery.c',
  'inputstream.c',
  'interfaces.c',
  'iostream.c',
  'outputstream.c',
  'pseudotcp.c',
  'stream.c',
])

gnome = import('gnome')

agent_enum_types = gnome.mkenums_simple('agent-enum-types', sources : agent_headers)
agent_enum_types_c = agent_enum_types[0]
agent_enum_types_h = agent_enum_types[1]

libagent = static_library('agent',
  agent_enum_types, agent_sources,
  c_args: ['-DG_LOG_DOMAIN="libnice"'],
  include_directories: nice_incs,
  dependencies: nice_deps,
  install: false)
