#!/usr/bin/python

import argparse
import math
import sys


def _hash(b):
    a = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]
    a += ~(a<<15);
    a ^=  (a>>10);
    a +=  (a<<3);
    a ^=  (a>>6);
    a += ~(a<<11);
    a ^=  (a>>16);
    return a


def _put_byte(window, table, chain, pos, b):
    bytes = [
        window[(pos-3) & 0xffff],
        window[(pos-2) & 0xffff],
        window[(pos-1) & 0xffff],
        b
    ]
    window[pos & 0xffff] = b
    h = _hash(bytes) & 0xffff
    prev = table[h]
    table[h] = pos-3
    chain[(pos-3) & 0xffff] = prev


def _match(window, pos, bytes):
    last = len(bytes)-1
    if window[(pos+last) & 0xffff] != bytes[last]:
        return False
    for i in range(last):
        if window[(pos+i) & 0xffff] != bytes[i]:
            return False
    return True


def _matches(window, table, chain, pos, mlen, moff):
    assert mlen >= 4
    if moff < mlen:
        return [moff] # Too much trouble
    mpos = pos - moff
    match = [window[(mpos+i) & 0xffff] for i in range(mlen)]
    bytes = match[:4]
    h = _hash(bytes) & 0xffff
    mlist = []
    p = table[h]
    while p is not None and p >= pos - 0xffff:
        if _match(window, p, match):
            mlist.append(pos - p)
        p = chain[p & 0xffff]
    if moff not in mlist:
        mlist.append(moff)
    return mlist


def scan_lz4(cover, skip_bytes=4):
    '''Scans an LZ4 string, finding how many bytes can be stored'''
    randbits = 0
    randpartbits = 0
    cover = bytearray(cover)
    window = bytearray(2**16)
    table = [None] * (2**16)
    chain = [None] * (2**16)
    pos = 0
    cpos = skip_bytes
    cend = len(cover)
    next_log = cend // 100
    while cpos < cend:
        if cpos > next_log:
            print cpos * 100 // cend, randbits // 8 * 100. / cpos
            next_log += cend // 100
        token = cover[cpos]
        cpos += 1
        llen = token >> 4
        mlen = token & 0xf
        
        if llen == 15:
            while cover[cpos] == 255:
                llen += 255
                cpos += 1
            llen += cover[cpos]
            cpos += 1
        
        while llen:
            _put_byte(window, table, chain, pos, cover[cpos])
            cpos += 1
            pos += 1
            llen -= 1
        
        if cpos == cend:
            break
        
        moff = cover[cpos] + (cover[cpos+1] << 8)
        cpos += 2
        
        if mlen == 15:
            while cover[cpos] == 255:
                mlen += 255
                cpos += 1
            mlen += cover[cpos]
            cpos += 1
        mlen += 4
        
        mlist = _matches(window, table, chain, pos, mlen, moff)
        assert len(mlist)
        
        if len(mlist) > 1:
            randbits += int(math.log(len(mlist), 2))
            randpartbits += math.log(len(mlist), 2)
        
        while mlen:
            _put_byte(window, table, chain, pos, window[(pos - moff) & 0xffff])
            pos += 1
            mlen -= 1
    return randbits // 8


def hide_lz4(cover, message, skip_bytes=4, store_len=True):
    '''Stores the message in an LZ4 string, raises IOError if out of space'''
    randbits = 0
    randpartbits = 0
    cover = bytearray(cover)
    window = bytearray(2**16)
    table = [None] * (2**16)
    chain = [None] * (2**16)
    pos = 0
    cpos = skip_bytes
    cend = len(cover)
    
    message = [ord(i) for i in message]
    if store_len:
        assert 0 < len(message) < 0xffff
        message = [len(message) & 0xff, (len(message) >> 8) & 0xff] + message
    msg_pos, msg_bit = 0, 0
    while cpos < cend:
        token = cover[cpos]
        cpos += 1
        llen = token >> 4
        mlen = token & 0xf
        
        if llen == 15:
            while cover[cpos] == 255:
                llen += 255
                cpos += 1
            llen += cover[cpos]
            cpos += 1
        
        while llen:
            _put_byte(window, table, chain, pos, cover[cpos])
            cpos += 1
            pos += 1
            llen -= 1
        
        if cpos == cend:
            break
        
        moff_pos = cpos
        moff = cover[cpos] + (cover[cpos+1] << 8)
        cpos += 2
        
        if mlen == 15:
            while cover[cpos] == 255:
                mlen += 255
                cpos += 1
            mlen += cover[cpos]
            cpos += 1
        mlen += 4
        
        mlist = _matches(window, table, chain, pos, mlen, moff)
        assert len(mlist)
        
        if len(mlist) > 1:
            bits = int(math.log(len(mlist), 2))
            randbits += bits
            which = 0
            for i in range(bits):
                bit = (message[msg_pos] >> msg_bit) & 1
                which += (bit << i)
                msg_bit += 1
                if msg_bit == 8:
                    msg_bit = 0
                    msg_pos += 1
                    if msg_pos == len(message):
                        break
            cover[moff_pos] = mlist[which] & 0xff
            cover[moff_pos + 1] = mlist[which] >> 8
            if msg_pos == len(message):
                break
        
        while mlen:
            _put_byte(window, table, chain, pos, window[(pos - moff) & 0xffff])
            pos += 1
            mlen -= 1
    if msg_pos < len(message):
        raise IOError
    return cover


def unhide_lz4(cover, skip_bytes=4, read_len=True):
    '''Reads the message from an LZ4 string'''
    randbits = 0
    randpartbits = 0
    cover = bytearray(cover)
    window = bytearray(2**16)
    table = [None] * (2**16)
    chain = [None] * (2**16)
    pos = 0
    cpos = skip_bytes
    cend = len(cover)
    
    message = [0]
    msg_pos, msg_bit = 0, 0
    msg_len = None
    while cpos < cend:
        token = cover[cpos]
        cpos += 1
        llen = token >> 4
        mlen = token & 0xf
        
        if llen == 15:
            while cover[cpos] == 255:
                llen += 255
                cpos += 1
            llen += cover[cpos]
            cpos += 1
        
        while llen:
            _put_byte(window, table, chain, pos, cover[cpos])
            cpos += 1
            pos += 1
            llen -= 1
        
        if cpos == cend:
            break
        
        moff_pos = cpos
        moff = cover[cpos] + (cover[cpos+1] << 8)
        cpos += 2
        
        if mlen == 15:
            while cover[cpos] == 255:
                mlen += 255
                cpos += 1
            mlen += cover[cpos]
            cpos += 1
        mlen += 4
        
        mlist = _matches(window, table, chain, pos, mlen, moff)
        assert len(mlist)
        
        if len(mlist) > 1:
            bits = int(math.log(len(mlist), 2))
            randbits += bits
            which = mlist.index(moff)
            for i in range(bits):
                bit = (which >> i) & 1
                message[msg_pos] += bit << msg_bit
                msg_bit += 1
                if msg_bit == 8:
                    msg_bit = 0
                    msg_pos += 1
                    if read_len and msg_pos == 2:
                        msg_len = message[0] + (message[1] << 8)
                    if msg_len and msg_pos == msg_len + 2:
                        break
                    message.append(0)
            cover[moff_pos] = mlist[which] & 0xff
            cover[moff_pos + 1] = mlist[which] >> 8
            if msg_len and msg_pos == msg_len + 2:
                break
        
        while mlen:
            _put_byte(window, table, chain, pos, window[(pos - moff) & 0xffff])
            pos += 1
            mlen -= 1
    if read_len:
        message = message[2:]
    return ''.join([chr(i) for i in message])


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
        message = unhide_lz4(cover)
        print message
    elif args.message:
        assert len(args.message)
        cover = hide_lz4(cover, args.message)
        sys.stdout.write(cover)
    else:
        bytes = scan_lz4(cover)
        print '%d bytes of storage in %d (%.2f %%)', (
            bytes, len(cover), bytes * 100. / len(cover)
        )

