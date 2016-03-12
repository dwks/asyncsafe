#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void good(int s) {
    write(STDOUT_FILENO, "This handler is fine\n", 21);
}

void bad(int s) {
    puts("This handler is bad :(");
}

int main() {
    puts("ok");

    signal(SIGUSR1, good);
    signal(SIGUSR2, bad);

    raise(SIGUSR1);
    raise(SIGUSR2);

    puts("back in main");
    fprintf(stderr, "bye\n");

    return 0;
}
