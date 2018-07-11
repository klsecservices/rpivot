#!/usr/bin/env python

import sys

try:
    rpivot_type = sys.argv.pop(1).lower()
    if rpivot_type not in ('client', 'server'):
        raise IndexError('Bad rpivot type')
except IndexError:
    print('{} <server|client> ...'.format(sys.argv[0]))
    sys.exit(1)

if rpivot_type == 'client':
    import client
    client.main()
elif rpivot_type == 'server':
    import server
    server.main()
