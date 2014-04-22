#!/usr/bin/env python
#
# Copyright (c) 2014, Jan Varho <jan@varho.org>
# Some rights reserved, see COPYING


import argparse
import sys

from lz77steg import LZ77Steg, _hash


class SnappySteg(LZ77Steg):

    TOK_LITERAL = 0
    TOK_COPY1 = 1
    TOK_COPY2 = 2
    TOK_COPY4 = 3

    def get_varint(self):
        i, v = 0, 0
        while self.cover[self.cpos] & 0x80:
            v += (self.get_cbyte() & 0x7f) << (7 * i)
            i += 1
        v += self.get_cbyte() << (7 * i)
        return v

    def init(self, cover):
        super(SnappySteg, self).init(cover)
        self.end = self.get_varint()

    def get_tokens(self):
        '''Generator for tokens, must be implemented'''
        while self.pos < self.end:
            tag = self.get_cbyte()
            ttype = tag & 3

            if ttype == self.TOK_LITERAL:
                llen = 1 + (tag >> 2)
                if llen > 60:
                    llen = 1 + self.get_littleendian(llen - 60)
                yield (ttype, llen)
                continue

            opos = self.cpos
            if ttype == self.TOK_COPY1:
                mlen = 4 + ((tag >> 2) & 0x7)
                moff = self.get_cbyte() + ((tag & 0xe0) << 3)
            elif ttype == self.TOK_COPY2:
                mlen = 1 + (tag >> 2)
                moff = self.get_littleendian(2)
            else:
                assert ttype == self.TOK_COPY4
                mlen = 1 + (tag >> 2)
                moff = self.get_littleendian(4)
            yield (ttype, mlen, moff, opos)

    def is_match(self, t):
        '''Is token a match token?'''
        # Window is too small for 4-byte offsets
        if t[0] == self.TOK_LITERAL or t[0] == self.TOK_COPY4:
            return False
        return t[1] >= 4 # using 4-byte hash

    def update_window(self, t):
        '''Update window with token'''
        if t[0] == self.TOK_LITERAL:
            self.update_window_literal(t[1])
        else:
            self.update_window_match(t[1], t[2])

    def list_possible_matches_t(self, t):
        '''Return a list of possible matches for t'''
        tt, mlen, moff, opos = t
        if tt == self.TOK_COPY2 or tt == self.TOK_COPY4:
            return self.list_possible_matches(mlen, moff)
        elif tt == self.TOK_COPY1:
            return self.list_possible_matches(mlen, moff, maxoff=0x7ff)
        else:
            assert False

    def update_match(self, t, nmatch):
        '''Updates cover token to new match, must be implemented'''
        tt, mlen, moff, opos = t
        if tt == self.TOK_COPY2:
            self.cover[opos] = nmatch & 0xff
            self.cover[opos + 1] = nmatch >> 8
        elif tt == self.TOK_COPY1:
            self.cover[opos] = nmatch & 0xff
            self.cover[opos - 1] = self.cover[opos - 1] & 0x1f
            self.cover[opos - 1] += (nmatch >> 3) & 0xe0

    def get_index(self, mlist, t):
        '''Get the index of the match'''
        return mlist.index(t[2])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Snappy steganography')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('-d', '--decode', action='store_true')
    action.add_argument('-m', '--message')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('-i', '--inplace', action='store_true')
    output.add_argument('-o', '--output')
    parser.add_argument('FILE')
    args = parser.parse_args()

    with open(args.FILE) as f:
        cover = f.read()

    if args.decode:
        message = SnappySteg().retrieve(cover, nullterm=True)
        print message
    elif args.message:
        assert len(args.message)
        cover = SnappySteg().store(cover, args.message, nullterm=True)
        if args.output:
            with open(args.output, 'wb') as f:
                f.write(cover)
        elif args.inplace:
            with open(args.FILE, 'wb') as f:
                f.write(cover)
        else:
            sys.stdout.write(cover)
    else:
        s = SnappySteg()
        cap, pcap = s.scan(cover)
        clen = len(cover)
        print (
            'Size',
            'Compressed', 'ratio',
            'Stored', 'ratio',
            'Storable', 'ratio',
        )
        print (
            s.end,
            clen, clen * 100. / s.end,
            cap, cap * 100. / clen,
            pcap, pcap * 100. / clen,
        )

