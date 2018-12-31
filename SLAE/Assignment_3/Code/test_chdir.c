#include <stdio.h>
#include <errno.h>
#include <string.h>

extern int errno ;

int main () {

   int errnum;
   int pf = chdir(0x0001234);

   if (pf != 0) {
      errnum = errno;
      fprintf(stderr, "Value of errno: %d\n", errno);
      perror("Error printed by perror");
      fprintf(stderr, "Error opening file: %s\n", strerror( errnum ));
   }
   return 0;
}