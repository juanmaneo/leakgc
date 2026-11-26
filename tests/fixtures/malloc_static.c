#include <malloc.h>
#include <signal.h>
#include <stdlib.h>

void *keep[4];
/* Referenced so that the static image defines every hooked entry (R39). A
   static musl binary links an entry only when something references it. pvalloc
   and malloc_trim are glibc extensions, so they are left out elsewhere. */
void *entries[] = {
    (void *)free,          (void *)realloc,       (void *)calloc,
    (void *)memalign,      (void *)aligned_alloc, (void *)valloc,
    (void *)posix_memalign,
#ifdef __GLIBC__
    (void *)pvalloc,
    (void *)malloc_trim,
#endif
};

int main(void) {
    keep[0] = malloc(16);
    keep[1] = malloc(100);
    keep[2] = malloc(1000);
    keep[3] = malloc(40000);
    raise(SIGSTOP);
    return 0;
}
