#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"[INSERT_YOUR_SHELLCODE_HERE]";

main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}