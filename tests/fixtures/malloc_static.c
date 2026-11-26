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

/* glibc's allocator keeps `_int_malloc` in the image, and the injection checks
   look for it (R37). On other libcs this stand-in gives the fake tests the same
   shape, so they reach the injection code everywhere. Nothing calls it. The
   padding keeps the crash tests' offsets inside it. */
#ifndef __GLIBC__
__asm__(".globl _int_malloc\n"
        ".type _int_malloc, @function\n"
        "_int_malloc:\n"
        ".rept 64\n"
        "nop\n"
        ".endr\n"
        "ret\n"
        ".size _int_malloc, .-_int_malloc\n");
#endif

int main(void) {
    keep[0] = malloc(16);
    keep[1] = malloc(100);
    keep[2] = malloc(1000);
    keep[3] = malloc(40000);
    raise(SIGSTOP);
    return 0;
}
