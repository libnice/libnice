docpath = join_paths(nice_datadir, 'gtk-doc', 'html')

ignore_headers = [
  'conncheck.h',
  'discovery.h',
  'stream.h',
  'component.h',
  'agent-priv.h',
  'iostream.h',
  'inputstream.h',
  'outputstream.h',
  'gstnice.h',
  'gstnicesrc.h',
  'gstnicesink.h',
  'md5.h',
  'sha1.h',
  'stunhmac.h',
  'utils.h',
  'rand.h',
  'stun5389.h',
  'stuncrc32.h',
  'stund.h',
  'agent-signals-marshal.h',
  'win32_common.h',
]

gnome.gtkdoc('libnice',
             main_xml: 'libnice-docs.xml',
             namespace: 'nice',
             mode: 'none',
             src_dir: ['agent', 'stun'],
             dependencies: libnice_dep,
             scan_args: [
               '--rebuild-types',
               #'--deprecated-guards=G_DISABLE_DEPRECATED',
               #'--ignore-decorators=' + '|'.join(ignore_decorators),
               '--ignore-headers=' + ' '.join(ignore_headers),
             ],
             html_assets: [
               'states.png',
             ],
             fixxref_args:[
               '--html-dir=' + docpath,
             ],
             mkdb_args: [ # not sure if these need to be specified explicitly here
               '--xml-mode',
               '--output-format=xml',
               '--name-space=Nice',
             ],
             install: true)

# If we ever need to regenerate this diagram.
# Since it’s not expected to change much, let’s not depend on GraphViz to
# build the docs (that's also why we don't use find_program('dot') here)
run_target('update-states.png',
  command: ['dot',
            '-Tpng',
            '-o', join_paths(meson.current_source_dir(), 'states.png'),
            '-Gsize=9.6,2.9!',
            '-Gdpi=200',
            files('states.gv')])
