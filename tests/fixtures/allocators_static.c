#include <malloc.h>
#include <stdlib.h>
#include <sys/mman.h>

void *keep[5];

int main(void) {
    keep[0] = calloc(3, 40);
    keep[1] = memalign(64, 100);
    keep[2] = aligned_alloc(32, 128);
    keep[3] = valloc(10);
#ifdef __GLIBC__
    keep[4] = pvalloc(20);
#else
    keep[4] = valloc(20);
#endif
    free(keep[1]);
    keep[1] = NULL;
    /* A trapped call after the last allocation, so the ring is read (D34). */
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return 0;
}
