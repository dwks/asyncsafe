#include <unistd.h>
#include "safe.h"
#include "plt.h"

#define SIG_WRITE(s) \
    write(STDERR_FILENO, s, sizeof s)

// appends data onto a, returns ptr to end, does not NULL terminate
char *append(char *a, const char *data) {
    while(*data) *a++ = *data++;
    return a;
}

void asyncsafe_violation(int index) {
    // do whatever you want when an invalid function is called

    Elf64_Sym *sym = plt_symbol[index];
    const char *name = elf.dynstr + sym->st_name;

    char message[256];
    char *p = message;

    p = append(p, "asyncsafe violation! handler for signal ");

    // signals are at most two decimal digits...
    if(current_signal >= 10) *p++ = current_signal / 10 + '0';
    *p++ = current_signal % 10 + '0';

    p = append(p, " called [");
    p = append(p, name);
    p = append(p, "]\n");
    *p = 0;

    write(STDERR_FILENO, message, p - message);

    // By default, fall through and run the requested function.
    // The PLT entry will be reset so the violation function will
    // only be called once per function per signal handler.
}
