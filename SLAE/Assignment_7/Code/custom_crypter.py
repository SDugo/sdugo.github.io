#!/usr/bin/python

"""
 Filename:   custom_crypter.py
 Author:     Samuel Dugo
 SLAE-ID:    SLAE-1376
 Purpose:    Assignment #7 of SLAE certification. This code will encrypt a provided shellcode, and then it will attempt to decrypt and execute the shellcode.
"""

import binascii
from ctypes import *
import argparse

parser = argparse.ArgumentParser(description='This is a demo script that will encrypt/decrypt a text string using multiple rounds of XOR based on the key lenght.')
parser.add_argument('-e','--encrypt', help='Call encryption functionality', action='store_true')
parser.add_argument('-d','--decrypt', help='Call decryption functionality', action='store_true')
args = parser.parse_args()


def encryption():
    try:
        print('Starting encryption')
        plain_text = input('Enter text to encrypt: ')
        print('Text to encrypt: ' +str(plain_text))
        encryption_key = raw_input('Enter encryption key: ')
        encryption_key_decimal = int(str(encryption_key).encode("hex"),16)
        encrypted_text = []
        for x in plain_text:
            decimal_value = int(str(x).encode("hex"),16)
            encrypted_char = 0
            for k in xrange(0,len(encryption_key)):
                encrypted_char = int(encrypted_char) + (decimal_value ^ encryption_key_decimal)
            encrypted_char = hex(encrypted_char)
            encrypted_text.append(encrypted_char)
        print('Encrypted text is: ' +','.join(encrypted_text))
    except:
        print('An error occured during encryption process.')
        print('Ensure the text introduced is surrounded by double quotes and ensure the text introduced is a shellcode representation like "\\x80".')

def decryption():
    try:
        print('Starting decryption')
        encrypted_text = input('Enter text to decrypt using commas: ')
        print('Text to decrypt: ' + str(encrypted_text))
        decryption_key = raw_input('Enter decryption key: ')
        decryption_key_decimal = int(str(decryption_key).encode("hex"),16)
        decrypted_text = []
        decrypted_text_exec = []
        for y in encrypted_text.split(','):
            encrypted_decimal = int(y,0)
            divided_result = encrypted_decimal/len(decryption_key)
            decrypted_char = chr(divided_result ^ decryption_key_decimal)
            decrypted_text.append('\\x' + str(decrypted_char).encode('hex'))
            decrypted_text_exec.append(decrypted_char)
        print('Decrypted text is: ' + ''.join(decrypted_text))
        print('Trying to run the decrypted shellcode')
        runshellcode(''.join(decrypted_text_exec))
    except:
        print('An error occured during decryption process.')
        print('Ensure the text introduced is surrounded by double quotes and ensure the text introduced is a shellcode representation separated by commas like "0x80,0x61".')

def runshellcode(shellcode):
    try:
        print(shellcode)
        libc = CDLL('libc.so.6')
        sc = c_char_p(shellcode)
        size = len(shellcode)
        addr = c_void_p(libc.valloc(size))
        memmove(addr, sc, size)
        libc.mprotect(addr, size, 0x7)
        run = cast(addr, CFUNCTYPE(c_void_p))
        run()
    except:
        print('An error occured while trying to execute the decrypted shellcode')


def main():
    if args.encrypt:
        encryption()
    elif args.decrypt:
        decryption()

if __name__ == "__main__":
    main()