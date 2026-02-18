// gcc -o chal main.c -fno-stack-protector -O0

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

// ROP gadgets
__asm__(
    "pop %rdi\nret\n"
    "pop %rsi\nret\n"
    "pop %rdx\nret\n"
);

// call win(0xdeadbeefcafebabe, 0x1122334455667788, 0xabcdabcdabcdabcd) to get a shell!

void win(unsigned long long param1, unsigned long long param2, unsigned long long param3) {
    char command[] = "/bin/sh";
    
    if(param1 == 0xdeadbeefcafebabe) {
        printf("Check 1 passed: param1 == 0xdeadbeefcafebabe\n");
    } else {
        printf("Check 1 failed: param1 != 0xdeadbeefcafebabe (actual: %llx)\n", param1);
        exit(1);
    }

    if (param2 == 0x1122334455667788) {
        printf("Check 2 passed: param2 == 0x1122334455667788\n");
    } else {
        printf("Check 2 failed: param2 != 0x1122334455667788 (actual: %llx)\n", param2);
        exit(1);
    }

    if (param3 == 0xabcdabcdabcdabcd) {
        printf("Check 3 passed: param3 == 0xabcdabcdabcdabcd\n");
    } else {
        printf("Check 3 failed: param3 != 0xabcdabcdabcdabcd (actual: %llx)\n", param3);
        exit(1);
    }

    printf("All checks passed! Spawning shell...\n");
    execve(command, NULL, NULL);
}

int main(void) {
    char buffer[64];
    printf("address of win function: %p\n", win);
    printf("input > ");
    gets(buffer);
    return 0;
}

__attribute__((constructor))
void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}