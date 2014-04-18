#!/usr/bin/python

import argparse
import snappy
import sys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LZ4 compress')
    parser.add_argument('FILE')
    args = parser.parse_args()
    
    with open(args.FILE) as f:
        s = f.read()
    
    c = snappy.compress(s)
    sys.stdout.write(c)
    
