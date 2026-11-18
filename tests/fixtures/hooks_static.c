#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>

void *keep[2];
void *volatile nothing = NULL;

int main(void) {
    void *first = malloc(16);
    void *second = malloc(100);
    second = realloc(second, 200);
    keep[0] = second;
    keep[1] = realloc(nothing, 40000);
    free(first);
    /* A trapped call after the last allocation, so the ring is read (D34). */
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    raise(SIGSTOP);
    return 0;
}
