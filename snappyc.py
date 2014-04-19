#!/usr/bin/env python
#
# Copyright (c) 2014, Jan Varho <jan@varho.org>
# Some rights reserved, see COPYING


import argparse
import snappy
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Snappy compress')
    parser.add_argument('-o', '--output')
    parser.add_argument('FILE')
    args = parser.parse_args()

    with open(args.FILE) as f:
        s = f.read()

    c = snappy.compress(s)

    if args.output:
        with open(args.output, 'wb') as f:
            f.write(c)
    else:
        sys.stdout.write(c)

