#!/usr/bin/env python
#
# Copyright (c) 2014, Jan Varho <jan@varho.org>
# Some rights reserved, see COPYING


import argparse
import snappy


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Snappy comparison')
    parser.add_argument('FILE1')
    parser.add_argument('FILE2')
    args = parser.parse_args()

    with open(args.FILE1) as f:
        s1 = f.read()
    with open(args.FILE2) as f:
        s2 = f.read()

    if s1 != s2:
        print 'Snappy encodings differ'

    if snappy.decompress(s1) == snappy.decompress(s2):
        print 'Decompressed files match'
    else:
        print 'Decompressed files differ'

