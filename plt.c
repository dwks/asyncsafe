#define _GNU_SOURCE
#include <stdio.h>
#include "allow.h"
#include "safe.h"
#include "print.h"

/* --- Overwriting and restoring PLT entries --- */

size_t plt_count;
unsigned char *plt_allowed;
Elf64_Sym **plt_symbol;
unsigned long *plt_orig_address;

/*
  first PLT entry
    ff 35 02 06 20 00     pushq  0x200602(%rip)         # 0x600a68
    ff 25 04 06 20 00     jmpq   *0x200604(%rip)        # 0x600a70
    0f 1f 40 00           nopl   0x0(%rax)
  normal PLT entry
    <raise@plt+0>:   ff 25 02 06 20 00  jmpq   *0x200602(%rip)        # 0x600a78
    <raise@plt+6>:   68 00 00 00 00     pushq  $0x0
    <raise@plt+11>:  e9 e0 ff ff ff     jmpq   0x400460
*/

void *orig_resolve;

static void change_resolve_func(elf_t *elf, int hijack) {
    unsigned long handler = *(unsigned int *)(elf->plt + 8) + elf->plt + 8 + 4;
    printf("handler %lx\n", handler);

    if(hijack) {
        orig_resolve = (void *) *(unsigned long *)handler;

        extern void asyncsafe_resolve_asm(void);
        *(unsigned long *)handler = (unsigned long)&asyncsafe_resolve_asm;
    }
    else {
        *(unsigned long *)handler = (unsigned long)orig_resolve;
    }
}

static void reset_plt_entries(elf_t *elf) {
    Elf64_Rela *data = elf->map + elf->rela_plt_offset;
    for(size_t i = 0; i < plt_count; i ++) {
        Elf64_Rela *r = &data[i];
        unsigned long address   = base_address + r->r_offset;
        unsigned long type      = ELF64_R_TYPE(r->r_info);
        unsigned long symbol    = ELF64_R_SYM(r->r_info);

        // every relocation in .rela.plt should have this type, but double-check
        if(type != R_X86_64_JUMP_SLOT) continue;

        Elf64_Sym *symtab = (Elf64_Sym *)(elf->map + elf->dynsym->sh_offset);
        Elf64_Sym *sym = symtab + symbol;
        const char *name = elf->dynstr + sym->st_name;

        int good = is_allowed(name);

        printf("%s plt entry at %lx (index %lu) for [%s]\n",
            good ? "allow" : "BLOCK", address, symbol, name);

        plt_symbol[i] = sym;
        plt_allowed[i] = good;
        if(!good) {
            plt_orig_address[i] = *(unsigned long *)address;
            *(unsigned long *)address = elf->plt + 16*(i+1) + 6;
        }
    }
}

static void restore_plt_entries(elf_t *elf) {
    puts("restore original plt entries");
    Elf64_Rela *data = elf->map + elf->rela_plt_offset;
    for(size_t i = 0; i < plt_count; i ++) {
        Elf64_Rela *r = &data[i];
        unsigned long address   = base_address + r->r_offset;
        if(!plt_allowed[i] && plt_orig_address[i]) {
            *(unsigned long *)address = plt_orig_address[i];
        }
    }
}

void enable_intercept(void) {
    change_resolve_func(&elf, 1);
    reset_plt_entries(&elf);
}

void disable_intercept(void) {
    change_resolve_func(&elf, 0);
    restore_plt_entries(&elf);  // this step is optional!
}

