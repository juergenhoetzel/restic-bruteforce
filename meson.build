project('restic-brute', 'c')
ssl_dep = dependency('openssl')
thread_dep = dependency('threads')
# byte order
conf = configuration_data()
if build_machine.endian() == 'big'
  conf.set('BIGENDIAN', 1)
else
  conf.set('BIGENDIAN', 0)
endif
configure_file(output: 'config.h', configuration: conf)
executable('restic-brute', ['main.c', 'util.c', 'poly1305-donna/poly1305-donna.c'], dependencies : [ssl_dep, thread_dep])
