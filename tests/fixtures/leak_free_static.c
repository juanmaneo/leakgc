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

static void map_page(void) {
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
