
import math


def _hash(b):
    a = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]
    a += ~(a<<15);
    a ^=  (a>>10);
    a +=  (a<<3);
    a ^=  (a>>6);
    a += ~(a<<11);
    a ^=  (a>>16);
    return a


class LZ77Steg(object):
    
    def init(self, cover):
        '''Will be called prior to scan/store/retrieve'''
        self.cover = bytearray(cover)
        self.window = bytearray(2**16)
        self.table = [None] * (2**16)
        self.chain = [None] * (2**16)
        self.pos = self.cpos = 0
    
    def get_tokens(self):
        '''Generator for tokens, must be implemented'''
        raise NotImplementedError
    
    def is_match(self, t):
        '''Is token a match token?'''
        raise NotImplementedError
    
    def get_cbyte(self):
        self.cpos += 1
        return self.cover[self.cpos - 1]
    
    def get_littleendian(self, bytes):
        v = 0
        for i in range(bytes):
            v += self.get_cbyte() << (8 * i)
        return v
    
    def put_byte(self, b):
        bytes = [
            self.window[(self.pos-3) & 0xffff],
            self.window[(self.pos-2) & 0xffff],
            self.window[(self.pos-1) & 0xffff],
            b
        ]
        self.window[self.pos & 0xffff] = b
        h = _hash(bytes) & 0xffff
        prev = self.table[h]
        self.table[h] = self.pos-3
        self.chain[(self.pos-3) & 0xffff] = prev
        self.pos += 1
    
    def update_window_literal(self, llen):
        while llen:
            self.put_byte(self.get_cbyte())
            llen -= 1
    
    def update_window_match(self, mlen, moffset):
        while mlen:
            self.put_byte(self.window[(self.pos - moffset) & 0xffff])
            mlen -= 1
    
    def update_window(self, t):
        '''Update window with token, can use the above two'''
        raise NotImplementedError
    
    def scan(self, cover):
        '''Scans cover for capacity'''
        self.init(cover)
        capacity = 0
        for t in self.get_tokens():
            if self.is_match(t):
                mlist = self.list_possible_matches(t)
                bits = int(math.log(len(mlist), 2))
                capacity += bits
            self.update_window(t)
        return capacity // 8

    def get_message_bits(self, bits):
        index = 0
        for i in range(bits):
            bit = (self.message[self.mpos] >> self.mbit) & 1
            index += (bit << i)
            self.mbit += 1
            if self.mbit == 8:
                self.mbit = 0
                self.mpos += 1
                if self.mpos == self.mlen:
                    return index, True
        return index, False
    
    def list_possible_matches(self, t):
        '''Return a list of possible matches for t'''
        raise NotImplementedError
    
    def update_match(self, t, nmatch):
        '''Updates cover token to new match, must be implemented'''
        raise NotImplementedError
    
    def store(self, cover, message, storelen=False, nullterm=False):
        '''Stores message in cover, returning the modified'''
        self.init(cover)
        self.message = [ord(i) for i in message]
        if storelen and len(message) <= 0xffff:
            ol = len(message)
            self.message = [ol & 0xff, ol >> 8] + self.message
        if nullterm:
            self.message.append(0)
        self.mpos = 0
        self.mbit = 0
        self.mlen = len(self.message)
        for t in self.get_tokens():
            if self.is_match(t):
                mlist = self.list_possible_matches(t)
                bits = int(math.log(len(mlist), 2))
                index, exit = self.get_message_bits(bits)
                nmatch = mlist[index]
                self.update_match(t, nmatch)
                if exit:
                    break
            self.update_window(t)
        return self.cover
    
    def set_message_bits(self, bits, index):
        for i in range(bits):
            bit = (index >> i) & 1
            self.message[self.mpos] += bit << self.mbit
            self.mbit += 1
            if self.mbit == 8:
                self.mbit = 0
                self.mpos += 1
                if self.mpos == self.mlen:
                    return True
                self.message.append(0)
        return False
    
    def get_index(self, mlist, t):
        '''Get the index of the match'''
        raise NotImplementedError
    
    def retrieve(self, cover, retrievelen=False, nullterm=False):
        '''Retrieves message from cover'''
        self.init(cover)
        self.message = [0]
        self.mpos = 0
        self.mbit = 0
        self.mlen = -1
        for t in self.get_tokens():
            if self.is_match(t):
                mlist = self.list_possible_matches(t)
                bits = int(math.log(len(mlist), 2))
                ompos = self.mpos
                if self.set_message_bits(bits, self.get_index(mlist, t)):
                    break
                if nullterm and self.mpos > ompos:
                    if 0 in self.message[ompos:self.mpos]:
                        break
                if retrievelen and self.mpos == 2:
                    self.mlen = 2 + self.message[0] + (self.message[1] << 8)
            self.update_window(t)
        if retrievelen:
            self.message = self.message[2:]
        if nullterm:
            while self.message[-1] == 0:
                self.message = self.message[:-1]
        return ''.join([chr(i) for i in self.message])


