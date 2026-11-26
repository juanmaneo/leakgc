/* A stand-in for libc.so.6 in the install tests. It has the ten entry points
   that the install hooks, and a static `_int_malloc` that the internal-range
   lookup finds. It is a bump allocator that never frees, and it is never run.
   Build it with -O0 so every entry is long enough to hold a 5-byte jump. */
#include <stddef.h>

static char arena[1 << 20];
static size_t used;
static size_t calls;

__attribute__((noinline)) static void count(void) { calls++; }

__attribute__((noinline)) static void *_int_malloc(size_t size) {
    void *out = arena + used;
    used += (size + 15) & ~(size_t)15;
    return out;
}

void *malloc(size_t size) {
    count();
    return _int_malloc(size);
}

void free(void *ptr) {
    count();
    (void)ptr;
}

void *realloc(void *ptr, size_t size) {
    count();
    (void)ptr;
    return _int_malloc(size);
}

void *calloc(size_t count_, size_t size) {
    count();
    return _int_malloc(count_ * size);
}

void *memalign(size_t align, size_t size) {
    count();
    (void)align;
    return _int_malloc(size);
}

void *aligned_alloc(size_t align, size_t size) {
    count();
    (void)align;
    return _int_malloc(size);
}

void *valloc(size_t size) {
    count();
    return _int_malloc(size);
}

void *pvalloc(size_t size) {
    count();
    return _int_malloc(size);
}

int posix_memalign(void **out, size_t align, size_t size) {
    count();
    (void)align;
    *out = _int_malloc(size);
    return 0;
}

int malloc_trim(size_t pad) {
    count();
    (void)pad;
    return 0;
}
