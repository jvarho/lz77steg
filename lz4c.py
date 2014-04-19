#!/usr/bin/env python
#
# Copyright (c) 2014, Jan Varho <jan@varho.org>
# Some rights reserved, see COPYING


import argparse
import lz4
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LZ4 compress')
    parser.add_argument('-o', '--output')
    parser.add_argument('FILE')
    args = parser.parse_args()

    with open(args.FILE) as f:
        s = f.read()

    c = lz4.dumps(s)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(c)
    else:
        sys.stdout.write(c)

