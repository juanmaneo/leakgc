#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *block = malloc(1 << 20);
    if (!block) return 1;
    block[0] = 1;
    free(block);
    puts("hello");
    return 0;
}
