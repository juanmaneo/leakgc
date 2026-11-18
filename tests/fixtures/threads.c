#include <pthread.h>
#include <stdio.h>

static void *work(void *arg) {
    (void)arg;
    return NULL;
}

int main(void) {
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) pthread_create(&threads[i], NULL, work, NULL);
    for (int i = 0; i < 4; i++) pthread_join(threads[i], NULL);
    puts("threads");
    return 0;
}
