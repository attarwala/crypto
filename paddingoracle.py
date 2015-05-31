#!/usr/bin/env python2

import urllib2, sys, encodings

block_size = 16

ct = map(ord, "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4".decode("hex")) 
ct = map(chr, ct)

class PaddingOracle(object):
    def __init__(self):
        self.TARGET = 'http://crypto-class.appspot.com/po?er='
    def query(self, q):
        target = self.TARGET + urllib2.quote(q)
        req = urllib2.Request(target)
        try:
            f = urllib2.urlopen(req)
        except urllib2.HTTPError, e:
            if e.code == 404:
                return True # good padding
            return False # bad padding

def guesses():
    for i in range(0,256):
        yield chr(i)

def bust(block):
    #plain text
    pt = [" "] * 16
    #First get the ciphertext block that we are trying to guess
    c = ct[(block*block_size):(block+1)*block_size]
    ctblock = ct[(block*block_size):(block+1)*block_size]
    #guess for all 16 bytes of a block, and each byte has 256 guesses
    for i in range(0, block_size):
        #Get the ct of the byte that we are trying to guess
        b = ctblock[block_size - i - 1]
        #padding value is equal to the byte_num
        pad = i + 1
        guessed = False
        skippedg = 0
        for j in range(0, i):
            x = ord(pt[block_size - j - 1]) ^ pad
            c[block_size - j - 1] = chr(ord(ctblock[block_size - j - 1]) ^ x)
        for g in guesses():
            if ord(g) == pad:
                skippedg = ord(g)
            else:
                #The guess we want to try is ciphertext-byte xor g xor pad
                x = ord(b) ^ ord(g) ^ pad
                c[block_size - i - 1] = chr(x)
                #Always send atleast 2 blocks
                q1 = ''.join(c).encode('hex')
                q2 = ''.join(ct[(block + 1)*block_size:(block+2)*block_size]).encode('hex')
                q = q1 + q2
                if PaddingOracle().query(q) == True:
                    #guessed the correct pad
                    pt[block_size - i - 1] = chr(ord(g))
                    guessed = True
                    break
            if not guessed:
                pt[block_size - i - 1] = chr(skippedg)
    return ''.join(pt)


if __name__ == "__main__":
    size = len(ct)
    nblocks = size / block_size
    blocks = range(0, nblocks - 1)
    answer=""
    for block in blocks:
        answer = answer + bust(block)
        print answer
