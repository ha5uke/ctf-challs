// gcc -o chal main.c -fno-pie -no-pie
#include <stdio.h>
#include <string.h>
#include <unistd.h>


/*
** How to get the address of `win` **

  $ nm chal | grep win
  XXXXXXXXX

This address is **fixed** across executions, because the challenge binary
`chal` is compiled with -fno-pie (i.e., without position-independent code).
*/
void win() {
    execve("/bin/sh", NULL, NULL);
}

int main(void) {
    int integers[100], pos;

    /* disable stdio buffering */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("pos > ");
    scanf("%d", &pos);
    if (pos >= 100) {
        puts("You're a hacker!");
        return 1;
    }
    printf("val > ");
    scanf("%d", &integers[pos]);

    return 0;
}
