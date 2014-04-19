#!/usr/bin/python

import argparse
import lz4

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LZ4 comparison')
    parser.add_argument('FILE1')
    parser.add_argument('FILE2')
    args = parser.parse_args()

    with open(args.FILE1) as f:
        s1 = f.read()
    with open(args.FILE2) as f:
        s2 = f.read()

    if s1 != s2:
        print 'LZ4 encodings differ'

    if lz4.loads(s1) == lz4.loads(s2):
        print 'Decompressed files match'
    else:
        print 'Decompressed files differ'

