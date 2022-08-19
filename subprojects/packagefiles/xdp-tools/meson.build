project('libxdp', 'c', version: '1.2.3')

libxdp_libs = custom_target('libxdp',
    command: [
        find_program('compile.sh'),
        '@CURRENT_SOURCE_DIR@',
        meson.current_build_dir(),
    ],

    input: ['configure'],

    output: [
      'libxdp.a',
      'libbpf.a',
    ],

    # FIXME: (mansour) fix this:
    # - make this better fit with gramine build process, i.e.:
    #    * libxdp should only be built if xdp is enabled with gramine.
    #    * we should install libxdp.so to gramine.runtime too.
    build_always: true
)

libxdp_inc = include_directories('headers')

libxdp_dep = declare_dependency(
    link_with: libxdp_libs,
    include_directories: libxdp_inc,
)
