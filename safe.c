#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include "elfmap.h"

#define printf(...)
#define puts(...)

static elf_t elf;
static int initialized = 0;

unsigned long sym_index[96/16];
unsigned long orig_address[96/16];
int plt_allowed[96/16];

void asyncsafe_init(void) {
    if(initialized) return;

    get_elf_info_for_pid(&elf, getpid());
    initialized = 1;
}

#define SIG_WRITE(s) \
    write(STDERR_FILENO, s, sizeof s)

void asyncsafe_violation(int index) {
    Elf64_Sym *symtab = (Elf64_Sym *)(elf.map + elf.dynsym->sh_offset);
    Elf64_Sym *sym = symtab + sym_index[index];
    const char *name = elf.dynstr + sym->st_name;

    SIG_WRITE("asyncsafe: violation! called [");
    int len = 0;
    while(name[len]) len++;
    write(STDERR_FILENO, name, len);
    SIG_WRITE("]\n");
}

const char *allowed[] = {
    "write"
};

void *orig_resolve;

void enable_normal(elf_t *elf) {
    unsigned long handler = *(unsigned int *)(elf->plt + 8) + elf->plt + 8 + 4;
    *(unsigned long *)handler = orig_resolve;
}

void erase_entries(elf_t *elf) {
    unsigned long handler = *(unsigned int *)(elf->plt + 8) + elf->plt + 8 + 4;
    printf("handler %lx\n", handler);
    orig_resolve = *(unsigned long *)handler;
    extern void asyncsafe_violation_asm(void);
    *(unsigned long *)handler = &asyncsafe_violation_asm;


    Elf64_Sym *symtab = (Elf64_Sym *)(elf->map + elf->dynsym->sh_offset);

    unsigned long base_address = 0;
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];

        // Note: 64-bit x86 always uses RELA relocations (not REL),
        // according to readelf source: see the function guess_is_rela()
        if(s->sh_type != SHT_RELA) continue;

        // We never use debug relocations, and they often contain relative
        // addresses which cannot be dereferenced directly (segfault).
        // So ignore all sections with debug relocations.
        const char *name = elf->shstrtab + s->sh_name;
        if(strstr(name, "debug")) continue;

        Elf64_Rela *data = elf->map + s->sh_offset;

        size_t count = s->sh_size / sizeof(*data);
        for(size_t i = 0; i < count; i ++) {
            Elf64_Rela *r = &data[i];
            unsigned long address   = base_address + r->r_offset;
            unsigned long type      = ELF64_R_TYPE(r->r_info);
            unsigned long symbol    = ELF64_R_SYM(r->r_info);
            unsigned long addend    = r->r_addend;

            if(type == R_X86_64_JUMP_SLOT) {
                Elf64_Sym *sym = symtab + symbol;
                const char *name = elf->dynstr + sym->st_name;
                int good = 0;
                for(size_t z = 0; z < sizeof(allowed)/sizeof(*allowed); z ++) {
                    if(strcmp(allowed[z], name) == 0) {
                        good = 1;
                        break;
                    }
                }

                printf("%s plt entry at %lx (index %d, addend %lx) for [%s]\n",
                    good ? "allow" : "BLOCK", address, symbol, addend, name);

                sym_index[i] = symbol;
                if(!good) {
                    orig_address[i] = *(unsigned long *)address;
                    *(unsigned long *)address = elf->plt + 16*(i+1) + 6;
                }
                plt_allowed[i] = good;
            }
        }
    }
}

void asyncsafe_toggle(int on) {
    if(on) {
        erase_entries(&elf);
    }
    else {
        enable_normal(&elf);
    }
}

/* --- Signal interception (signal, sigaction) --- */

typedef void (*sighandler_t)(int);
typedef void (*sigaction_t)(int, siginfo_t *, void *);

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
