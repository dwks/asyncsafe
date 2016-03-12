#ifndef ELFMAP_H
#define ELFMAP_H

#include <elf.h>
#include <stddef.h>  // for size_t
#include <sys/types.h>  // for pid_t

#ifdef __cplusplus
extern "C" {
#endif

typedef struct elf_t {
    /** Memory map of executable image.
    */
    void *map;
    
    /** Size of memory map.
    */
    size_t length;
    
    /** File descriptor associated with memory map.
    */
    int fd;
    
    Elf64_Ehdr *header;
    Elf64_Shdr *sheader;  // array
    Elf64_Phdr *pheader;  // array
    
    const char *shstrtab;
    const char *strtab;
    const char *dynstr;
    
    unsigned long *dynamic;  // pointer to _DYNAMIC

    unsigned long *got, *got_plt;
    unsigned long rela_plt, rela_plt_offset, rela_plt_size;
    Elf64_Shdr *symtab, *dynsym;
    unsigned long plt, plt_size;
    unsigned long plt_got, plt_got_size;
} elf_t;

void get_elf_info_for_pid(elf_t *elf, pid_t pid);
void get_elf_info_for_file(elf_t *elf, const char *filename);
void parse_elf_info_from_self(elf_t *elf, void *address);
void cleanup_elf_info(elf_t *elf);
int is_data_pointer(elf_t *elf, unsigned long ptr);

unsigned long get_elf_init_size(elf_t *elf);
const char *get_elf_soname(elf_t *elf);

#ifdef __cplusplus
}
#endif

#endif
