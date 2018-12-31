#include <stdio.h>
#include <sys/socket.h>

int main()
{
  int fd;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd == -1)
  {
      printf("Error opening socket\n");
      return -1;
  }
}