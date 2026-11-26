#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

void *sink;

static void leak(int n) {
    for (int i = 0; i < n; i++) {
        sink = malloc(1000);
        memset(sink, 0x5a, 16);
    }
}

/* The R37 check reads 1 KB of stack above the trapped mmap. glibc's startup
   leaves stale return addresses into malloc in main's frame, which would refuse
   the injected frees. Clearing a 2 KB frame here keeps that window clean. */
static void map_page(void) {
    volatile char pad[2048];
    memset((char *)pad, 0, sizeof pad);
    mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

int main(void) {
    leak(70);
    map_page();
    leak(70);
    size_t before = mallinfo2().uordblks;
    map_page();
    size_t after = mallinfo2().uordblks;
    const unsigned char *kept = sink;
    int live = kept[0] == 0x5a && kept[15] == 0x5a;
    fprintf(stderr, "drop %zu live %s\n", before - after, live ? "ok" : "lost");
    return live ? 0 : 1;
}
