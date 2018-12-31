#include <stdio.h>
#include <string.h>

unsigned char egg_hunter[] =  
"EGG_HUNTER_SHELLCODE";

unsigned char shellcode[] = 
"\x72\x34\x33\x46\x72\x34\x33\x46" //F34rF34r
"PAYLOAD_DESIRED";

int main(void)
{
    printf("Egghunter length: %d\n", strlen(egg_hunter));
    printf("Shellcode length: %d\n", strlen(shellcode));
    (*(void(*)(void))egghunter)();
    return 0;
}