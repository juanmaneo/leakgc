#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/mman.h>

void *block;
void *rejected;

int main(void) {
    if (posix_memalign(&block, 64, 100) != 0) {
        return 1;
    }
    /* An alignment that is not a multiple of sizeof(void *) is refused, and writes nothing. */
    if (posix_memalign(&rejected, 3, 50) != EINVAL || rejected != NULL) {
        return 2;
    }
#ifdef __GLIBC__
    malloc_trim(0);
#endif
    /* A trapped call after the last allocation, so the ring is read (D34). */
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return 0;
}
