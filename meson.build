project('restic-brute', 'c')
ssl_dep = dependency('openssl')
thread_dep = dependency('threads')
executable('restic-brute', ['main.c', 'util.c', 'poly1305-donna/poly1305-donna.c'], dependencies : [ssl_dep, thread_dep])
