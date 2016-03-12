#ifndef ELFMAP_H
#define ELFMAP_H

#include <elf.h>
#include <stddef.h>  // for size_t
#include <sys/types.h>  // for pid_t

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
    
    unsigned long plt, plt_size;
    Elf64_Shdr *rela_plt, *plt_got;
    Elf64_Shdr *symtab, *dynsym;
} elf_t;

void get_elf_info_for_pid(elf_t *elf, pid_t pid);
void get_elf_info_for_file(elf_t *elf, const char *filename);
void parse_elf_info_from_self(elf_t *elf, void *address);
void cleanup_elf_info(elf_t *elf);

#endif
