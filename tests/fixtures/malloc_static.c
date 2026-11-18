#include <signal.h>
#include <stdlib.h>

void *keep[4];

int main(void) {
    keep[0] = malloc(16);
    keep[1] = malloc(100);
    keep[2] = malloc(1000);
    keep[3] = malloc(40000);
    raise(SIGSTOP);
    return 0;
}
