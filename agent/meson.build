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

agent_enum_types_c =  gnome.mkenums('agent-enum-types.c', sources : agent_headers,
				    fhead: '#include <config.h>\n#include <glib-object.h>\n#include "agent.h"\n#include "pseudotcp.h"\n#include "agent-enum-types.h"',
				    fprod: '\n/* enumerations from "@filename@" */',
				    vhead: 'GType\n@enum_name@_get_type (void)\n{\n  static GType type = 0;\n  if (!type) {\n    static const G@Type@Value values[] = {',
				    vprod: '      { @VALUENAME@, "@VALUENAME@", "@valuenick@" },',
				    vtail: '      { 0, NULL, NULL }\n    };\n    type = g_@type@_register_static ("@EnumName@", values);\n  }\n  return type;\n}\n\n')

agent_enum_types_h = gnome.mkenums('agent-enum-types.h', sources : agent_headers,
				   fhead: '#ifndef __AGENT_ENUM_TYPES_H__\n#define __AGENT_ENUM_TYPES_H__ 1\n\n#include <glib-object.h>\n\nG_BEGIN_DECLS\n',
				   fprod: '/* enumerations from "@filename@" */\n',
				   vhead: 'GType @enum_name@_get_type (void) G_GNUC_CONST;\n#define NICE_TYPE_@ENUMSHORT@ (@enum_name@_get_type())\n',
					  ftail: 'G_END_DECLS\n\n#endif /* !AGENT_ENUM_TYPES_H */')


libagent = static_library('agent',
  agent_enum_types_c, agent_enum_types_h, agent_sources,
  c_args: ['-DG_LOG_DOMAIN="libnice"'],
  include_directories: nice_incs,
  dependencies: nice_deps,
  install: false)
