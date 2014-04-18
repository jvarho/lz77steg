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
                    llen = self.get_littleendian(llen - 60)
                yield (ttype, llen)
                continue
            
            opos = self.cpos
            if ttype == self.TOK_COPY1:
                mlen = 4 + ((tag >> 2) & 0x7)
                moff = self.get_cbyte() + ((tag & 0xe0) << 3)
            elif ttype == self.TOK_COPY2:
                mlen = 4 + (tag >> 2)
                moff = self.get_littleendian(2)
            else:
                assert type == self.TOK_COPY4
                assert False
                mlen = 4 + (tag >> 2)
                moff = self.get_littleendian(4)
            yield (ttype, mlen, moff, opos)
    
    def is_match(self, t):
        '''Is token a match token?'''
        # Other offset/match lengths not supported
        return t[0] == self.TOK_COPY2 and t[1] >= 4
    
    def update_window(self, t):
        '''Update window with token'''
        if t[0] == self.TOK_LITERAL:
            self.update_window_literal(t[1])
        else:
            self.update_window_match(t[1], t[2])
    
    def list_possible_matches(self, t):
        '''Return a list of possible matches for t'''
        tt, mlen, moff, opos = t
        assert tt == self.TOK_COPY2
        assert mlen >= 4, mlen
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
    
    def get_index(self, mlist, t):
        '''Get the index of the match'''
        return mlist.index(t[2])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Snappy steganography')
    parser.add_argument('-d', '--decode', action='store_true')
    parser.add_argument('-m', '--message')
    #parser.add_argument('-o', '--output')
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
        sys.stdout.write(cover)
    else:
        bytes = SnappySteg().scan(cover)
        print '%d bytes of storage in %d (%.2f %%)' % (
            bytes, len(cover), bytes * 100. / len(cover)
        )

