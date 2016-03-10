#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <dlfcn.h>
#include <unistd.h>
#include "elfmap.h"

static elf_t elf;
static int initialized = 0;
void asyncsafe_init(void) {
    if(initialized) return;

    get_elf_info_for_pid(&elf, getpid());
    initialized = 1;
}

typedef void (*sighandler_t)(int);
typedef void (*sigaction_t)(int, siginfo_t *, void *);

void asyncsafe_violation(void) {
    puts("asyncsafe: violation!");
}

unsigned long orig_address[96/16];

void asyncsafe_toggle(int on) {
    unsigned char *p = (void *)elf.plt;
    unsigned long plt_size = elf.plt_size;

    unsigned long index = 0;
    p += 16;  // skip first entry
    while(p[0] == 0xff && p[1] == 0x25 && index*16 < plt_size) {
        unsigned int *o = (unsigned int *)&p[2];
        unsigned long *v = (unsigned long *)(*o + (unsigned char *)o + 4);
        if(on) {
            orig_address[index] = *v;
            if(index != 2) {
                *v = 0xdead;
            }
        }
        else {
            *v = orig_address[index];
        }
        p += 16;
        index ++;
    }
}

sigaction_t orig_func[64];  // max signals
void asyncsafe_intercept(int signum, siginfo_t *info, void *context) {

    sigaction_t a = orig_func[signum];
    if(!a) return;

    puts("asyncsafe on  vvv");
    asyncsafe_toggle(1);

    a(signum, info, context);

    puts("asyncsafe off ^^^");
    asyncsafe_toggle(0);
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
