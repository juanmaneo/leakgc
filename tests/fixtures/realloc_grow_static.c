#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Phases, chosen by argv[1]. "small" grows blocks that must move, with another
   allocation after each growth. "big" grows one block past the mmap threshold.
   "null" calls realloc(NULL, n), which glibc tail-jumps into malloc. Each phase
   ends with a trapped mmap, so the ring is read (D34). */
int main(int argc, char **argv) {
    const char *phase = argc > 1 ? argv[1] : "small";
    char *kept[16];
    if (strcmp(phase, "small") == 0) {
        char *block = malloc(16);
        for (int i = 0; i < 12; i++) {
            block = realloc(block, (size_t)16 << (i + 1));
            if (block == NULL) {
                return 1;
            }
            kept[i] = malloc(16);
        }
        for (int i = 0; i < 12; i++) {
            free(kept[i]);
        }
        free(block);
    } else if (strcmp(phase, "big") == 0) {
        char *block = malloc(1024);
        for (int i = 0; i < 10; i++) {
            block = realloc(block, (size_t)2048 << i);
            if (block == NULL) {
                return 1;
            }
        }
        free(block);
    } else if (strcmp(phase, "null") == 0) {
        char *block = realloc(NULL, 64);
        if (block == NULL) {
            return 1;
        }
        free(block);
    } else {
        return 2;
    }
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return 0;
}
