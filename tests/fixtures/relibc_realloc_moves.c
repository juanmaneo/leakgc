#include <stddef.h>
#include <stdlib.h>

/* Grows one block by 37 bytes at a time, so realloc moves it and copies it
   many times. After each growth every byte is checked, so exit 0 means the
   contents survived every move. Exit 2 to 4 names the step that failed.
   Used by tests/libc_relibc.rs. */

static unsigned char pattern(size_t i) {
    return (unsigned char)(i * 7 + 3);
}

int main(void) {
    size_t n = 1;
    unsigned char *p = malloc(n);
    if (!p) {
        return 2;
    }
    p[0] = pattern(0);
    for (int step = 0; step < 2000; step++) {
        size_t next = n + 37;
        unsigned char *q = realloc(p, next);
        if (!q) {
            return 3;
        }
        p = q;
        for (size_t i = n; i < next; i++) {
            p[i] = pattern(i);
        }
        n = next;
        for (size_t i = 0; i < n; i++) {
            if (p[i] != pattern(i)) {
                return 4;
            }
        }
    }
    free(p);
    return 0;
}
