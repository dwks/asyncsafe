#ifndef PLT_H
#define PLT_H

#include <elf.h>

extern size_t plt_count;
extern unsigned char *plt_allowed;
extern Elf64_Sym **plt_symbol;
extern unsigned long *plt_orig_address;

extern void *orig_resolve;

void enable_intercept(void);
void disable_intercept(void);

#endif
