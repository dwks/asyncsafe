#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <string.h>
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

const char *allowed[] = {
    "write"
};

void erase_entries(elf_t *elf) {
    unsigned long handler = *(unsigned int *)(elf->plt + 8) + elf->plt + 8 + 4;
    printf("handler %lx\n", handler);
    *(unsigned long *)handler = &asyncsafe_violation;


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

                printf("%s plt entry at %lx for [%s]\n",
                    good ? "allow" : "BLOCK", address, name);

                if(!good) {
                    orig_address[i] = *(unsigned long *)address;
                    *(unsigned long *)address = &asyncsafe_violation;
                }
            }
        }
    }
}

void asyncsafe_toggle(int on) {
#if 0
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
#else
    erase_entries(&elf);
#endif
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
