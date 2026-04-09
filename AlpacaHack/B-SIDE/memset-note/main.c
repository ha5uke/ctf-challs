// gcc -o chal main.c -fno-pie -no-pie
#include <stdio.h>
#include <string.h>
#include <unistd.h>


void win() {
    execve("/bin/sh", NULL, NULL);
}

int main(void) {
    unsigned n = 0;
    char c = 0;
    char buf[100] = {0};
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    while (1) {
        printf("size > ");
        scanf("%u", &n);
        if (n == 0) break;
        printf("char > ");
        scanf(" %c", &c);
        memset(buf, c, n);
        puts(buf);
    }
    return 0;
}
