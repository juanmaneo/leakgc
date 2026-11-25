#include <stdlib.h>
#include <sys/mman.h>

void *kept;

int main(void) {
    void *local = malloc(555);
    kept = malloc(777);
    void *lost = malloc(333);
    lost = NULL;
    for (int i = 0; i < 64; i++) {
        free(malloc(16));
    }
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return local == NULL;
}
