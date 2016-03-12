#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // SEEK_END etc.
#include <fcntl.h>
#include <sys/mman.h>

#include "elfmap.h"
#include "print.h"

#define die(str) \
    puts(str), exit(1)

static void verify_elf(elf_t *elf);
static void find_basic(elf_t *elf);
static void find_strtab(elf_t *elf);
static void find_got_and_plt(elf_t *elf);

void get_elf_info_for_pid(elf_t *elf, pid_t pid) {
    char name[64];
    sprintf(name, "/proc/%d/exe", (int)pid);
    get_elf_info_for_file(elf, name);
}

void get_elf_info_for_file(elf_t *elf, const char *filename) {
    printf("getting ELF info for [%s]\n", filename);

    elf->fd = open(filename, O_RDONLY, 0);
    if(elf->fd < 0) die("can't open executable image\n");
    
    // find the length of the file
    elf->length = (size_t)lseek(elf->fd, 0, SEEK_END);
    lseek(elf->fd, 0, SEEK_SET);
    
    // make a private copy of the file in memory
    int prot = PROT_READ /*| PROT_WRITE*/;
    elf->map = mmap(NULL, elf->length, prot, MAP_PRIVATE, elf->fd, 0);
    if(elf->map == (void *)-1) die("can't mmap executable image\n");
    
    verify_elf(elf);
    
    find_basic(elf);
    find_strtab(elf);
    find_got_and_plt(elf);
}

void parse_elf_info_from_self(elf_t *elf, void *address) {
    elf->fd = -1;
    elf->length = 0;
    elf->map = address;
    
    verify_elf(elf);
    
    find_basic(elf);
    find_strtab(elf);
    find_got_and_plt(elf);
}

static void verify_elf(elf_t *elf) {
    // make sure this is an ELF file
    if(*(Elf64_Word *)elf->map != *(Elf64_Word *)ELFMAG) {
        die("executable image does not have ELF magic\n");
    }
    
    // check architecture type
    char type = ((char *)elf->map)[EI_CLASS];
    if(type != ELFCLASS64) {
        die("file is not 64-bit ELF, unsupported\n");
    }
}

static void find_basic(elf_t *elf) {
    elf->header = (Elf64_Ehdr *)elf->map;
    if(sizeof(Elf64_Shdr) != elf->header->e_shentsize) {
        die("header shentsize mismatch\n");
    }
    
    elf->sheader = (Elf64_Shdr *)(elf->map + elf->header->e_shoff);
    elf->pheader = (Elf64_Phdr *)(elf->map + elf->header->e_phoff);
}

static void find_strtab(elf_t *elf) {
    const char *shstrtab
        = elf->map + elf->sheader[elf->header->e_shstrndx].sh_offset;
    elf->shstrtab = shstrtab;
    
    elf->strtab = elf->dynstr = 0;
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        const char *name = shstrtab + s->sh_name;
        if(!strcmp(name, ".strtab")) {
            elf->strtab = elf->map + s->sh_offset;
        }
        if(!strcmp(name, ".dynstr")) {
            elf->dynstr = elf->map + s->sh_offset;
        }
    }
}

static void find_got_and_plt(elf_t *elf) {
    elf->plt = elf->plt_size = 0;
    elf->rela_plt = elf->plt_got = 0;
    elf->symtab = elf->dynsym = 0;
    
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        const char *name = elf->shstrtab + s->sh_name;
        if(!strcmp(name, ".plt")) {
            elf->plt      = (unsigned long)s->sh_addr;
            elf->plt_size = (unsigned long)s->sh_size;
        }
        else if(!strcmp(name, ".plt.got")) {
            elf->plt_got = s;
        }
        else if(!strcmp(name, ".rela.plt")) {
            elf->rela_plt = s;
        }
        else if(!strcmp(name, ".symtab")) {
            elf->symtab = s;
        }
        else if(!strcmp(name, ".dynsym")) {
            elf->dynsym = s;
        }
    }
}

void cleanup_elf_info(elf_t *elf) {
    munmap(elf->map, elf->length);
    close(elf->fd);
}
