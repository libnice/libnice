#!/usr/bin/env python3
#
# gen-map.py LIBNICE.SYM
import os
import sys

try:
    sym_file = sys.argv[1]
except:
    print('Usage: gen-map.py SYM-FILE')
    exit(-1)

f = open(os.path.join(sym_file), 'r')

print('''{
global:''')

for line in f:
    print('\t' + line.strip() + ';')

print('''local:
	*;
};''')

f.close()
