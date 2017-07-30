#!/usr/bin/env python3
#
# gen-def.py LIBNICE.SYM
import os
import sys

try:
    sym_file = sys.argv[1]
except:
    print('Usage: gen-def.py SYM-FILE')
    exit(-1)

f = open(os.path.join(sym_file), 'r')

print('EXPORTS')
for line in f:
    print('    ' + line.strip())

f.close()
