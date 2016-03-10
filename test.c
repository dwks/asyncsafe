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
    signal(SIGUSR1, good);
    signal(SIGUSR2, bad);

    raise(SIGUSR1);
    raise(SIGUSR2);

    return 0;
}
