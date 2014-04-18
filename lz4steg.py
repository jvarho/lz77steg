#!/usr/bin/python

import argparse
import sys

from lz77steg import LZ77Steg, _hash


def _match(window, pos, bytes):
    last = len(bytes)-1
    if window[(pos+last) & 0xffff] != bytes[last]:
        return False
    for i in range(last):
        if window[(pos+i) & 0xffff] != bytes[i]:
            return False
    return True


class LZ4Steg(LZ77Steg):
    
    TOK_LITERAL = 1
    TOK_MATCH = 2
    
    def get_tokens(self):
        '''Generator for tokens, must be implemented'''
        while self.cpos < self.cend:
            token = self.cover[self.cpos]
            self.cpos += 1
            llen = token >> 4
            mlen = token & 0xf
            
            if llen == 15:
                while self.cover[self.cpos] == 255:
                    llen += 255
                    self.cpos += 1
                llen += self.cover[self.cpos]
                self.cpos += 1
            
            if llen:
                yield (self.TOK_LITERAL, llen)
            
            if self.cpos == self.cend:
                return
            
            opos = self.cpos
            
            moff = self.cover[self.cpos] + (self.cover[self.cpos+1] << 8)
            self.cpos += 2
            
            if mlen == 15:
                while self.cover[self.cpos] == 255:
                    mlen += 255
                    self.cpos += 1
                mlen += self.cover[self.cpos]
                self.cpos += 1
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
    
    def scan(self, cover, skip=4):
        '''Scans cover for capacity'''
        self.init(cover)
        self.cpos += skip
        return super(LZ4Steg, self).scan()
    
    def list_possible_matches(self, t):
        '''Return a list of possible matches for t'''
        tt, mlen, moff, opos = t
        if moff < mlen:
            return [moff] # Too much trouble
        mpos = self.pos - moff
        match = [self.window[(mpos+i) & 0xffff] for i in range(mlen)]
        bytes = match[:4]
        h = _hash(bytes) & 0xffff
        mlist = []
        p = self.table[h]
        while p is not None and p >= self.pos - 0xffff:
            if _match(self.window, p, match):
                mlist.append(self.pos - p)
            p = self.chain[p & 0xffff]
        if moff not in mlist:
            mlist.append(moff)
        return mlist
    
    def update_match(self, t, nmatch):
        '''Updates cover token to new match, must be implemented'''
        self.cover[t[3]] = nmatch & 0xff
        self.cover[t[3] + 1] = nmatch >> 8
    
    def store(self, cover, message, skip=4):
        '''Stores message in cover, returning the modified'''
        self.init(cover)
        self.cpos += skip
        return super(LZ4Steg, self).store(message, nullterm=True)
    
    def get_index(self, mlist, t):
        '''Get the index of the match'''
        return mlist.index(t[2])
    
    def retrieve(self, cover, skip=4):
        '''Retrieves message from cover'''
        self.init(cover)
        self.cpos += skip
        return super(LZ4Steg, self).retrieve(nullterm=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LZ4 steganography')
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('-m', '--message')
    #parser.add_argument('-o', '--output')
    parser.add_argument('FILE')
    args = parser.parse_args()
    
    with open(args.FILE) as f:
        cover = f.read()
    
    if args.decode:
        message = LZ4Steg().retrieve(cover)
        print message
    elif args.message:
        assert len(args.message)
        cover = LZ4Steg().store(cover, args.message)
        sys.stdout.write(cover)
    else:
        bytes = LZ4Steg().scan(cover)
        print '%d bytes of storage in %d (%.2f %%)' % (
            bytes, len(cover), bytes * 100. / len(cover)
        )

