#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include "plt.h"
#include "elfmap.h"
#include "print.h"

/* --- Initialization & ELF processing--- */

elf_t elf;
unsigned long base_address = 0;

void asyncsafe_init(void) {
    static int initialized = 0;
    if(initialized) return;
    initialized = 1;

    maybe_enable_logging();

    get_elf_info_for_pid(&elf, getpid());

    plt_count = elf.plt_got_size;
    plt_allowed = calloc(plt_count, sizeof *plt_allowed);
    plt_symbol = calloc(plt_count, sizeof *plt_symbol);
    plt_orig_address = calloc(plt_count, sizeof *plt_orig_address);
}

/* --- Signal interception (signal, sigaction) --- */

typedef void (*sighandler_t)(int);
typedef void (*sigaction_t)(int, siginfo_t *, void *);

static sigaction_t orig_func[64];  // 64 = max signals
int current_signal;

static void asyncsafe_intercept(int signum, siginfo_t *info, void *context) {
    sigaction_t a = orig_func[signum];
    if(!a) return;

    current_signal = signum;

    puts("asyncsafe on  vvv");
    enable_intercept();

    a(signum, info, context);

    puts("asyncsafe off ^^^");
    disable_intercept();
}

sighandler_t signal(int signum, sighandler_t handler) {
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_handler = handler;

    struct sigaction oldact;

    sigaction(signum, &act, &oldact);
    return oldact.sa_handler;
}

int sigaction(int signum, const struct sigaction *act,
    struct sigaction *oldact) {

    asyncsafe_init();
    void *orig_sigaction = dlsym(RTLD_NEXT, "sigaction");

    printf("asyncsafe: intercept signal %d registration of handler %p\n",
        signum, act->sa_handler);

    orig_func[signum] = act->sa_sigaction;
    ((struct sigaction *)act)->sa_sigaction = asyncsafe_intercept;

    return ((int (*)(int, const struct sigaction *, struct sigaction *))orig_sigaction)(signum, act, oldact);
}
