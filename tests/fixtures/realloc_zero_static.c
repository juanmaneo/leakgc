#include <stdlib.h>
#include <sys/mman.h>

int main(void) {
    void *block = malloc(100);
    /* glibc frees the block inside realloc's own code and returns NULL. */
    void *none = realloc(block, 0);
    if (none != NULL) {
        return 1;
    }
    /* A trapped call after the last allocation, so the ring is read (D34). */
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return 0;
}
