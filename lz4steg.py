#!/usr/bin/env python
#
# Copyright (c) 2014, Jan Varho <jan@varho.org>
# Some rights reserved, see COPYING


import argparse
import sys

from lz77steg import LZ77Steg, _hash


class LZ4Steg(LZ77Steg):
    
    TOK_LITERAL = 1
    TOK_MATCH = 2
    
    def init(self, cover):
        super(LZ4Steg, self).init(cover)
        self.end = self.get_littleendian(4)
    
    def get_tokens(self):
        '''Generator for tokens, must be implemented'''
        while self.pos < self.end:
            token = self.get_cbyte()
            llen = token >> 4
            mlen = token & 0xf
            
            if llen == 15:
                while self.cover[self.cpos] == 255:
                    llen += self.get_cbyte()
                llen += self.get_cbyte()
            
            if llen:
                yield (self.TOK_LITERAL, llen)
            
            if self.pos == self.end:
                return
            
            opos = self.cpos
            
            moff = self.get_littleendian(2)
            
            if mlen == 15:
                while self.cover[self.cpos] == 255:
                    mlen += self.get_cbyte()
                mlen += self.get_cbyte()
            mlen += 4
            
            yield (self.TOK_MATCH, mlen, moff, opos)
    
    def is_match(self, t):
        '''Is token a match token?'''
        return t[0] == self.TOK_MATCH
    
    def update_window(self, t):
        '''Update window with token'''
        if t[0] == self.TOK_LITERAL:
            self.update_window_literal(t[1])
        elif t[0] == self.TOK_MATCH:
            self.update_window_match(t[1], t[2])
        else:
            raise TypeError
    
    def list_possible_matches_t(self, t):
        '''Return a list of possible matches for t'''
        tt, mlen, moff, opos = t
        return self.list_possible_matches(mlen, moff)
    
    def update_match(self, t, nmatch):
        '''Updates cover token to new match, must be implemented'''
        self.cover[t[3]] = nmatch & 0xff
        self.cover[t[3] + 1] = nmatch >> 8
    
    def get_index(self, mlist, t):
        '''Get the index of the match'''
        return mlist.index(t[2])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LZ4 steganography')
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('-m', '--message')
    parser.add_argument('-o', '--output')
    parser.add_argument('FILE')
    args = parser.parse_args()
    
    with open(args.FILE) as f:
        cover = f.read()
    
    if args.decode:
        message = LZ4Steg().retrieve(cover, nullterm=True)
        print message
    elif args.message:
        assert len(args.message)
        cover = LZ4Steg().store(cover, args.message, nullterm=True)
        if args.output:
            with open(args.output) as f:
                f.write(cover)
        else:
            sys.stdout.write(cover)
    else:
        s = LZ4Steg()
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

