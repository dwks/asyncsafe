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
static void find_dynamic(elf_t *elf);
static void find_got_and_plt(elf_t *elf);

void get_elf_info_for_pid(elf_t *elf, pid_t pid) {
    //printf("mapping executable for process %d...\n", (int)pid);
    
    char name[64];
    sprintf(name, "/proc/%d/exe", (int)pid);
    get_elf_info_for_file(elf, name);
}

void get_elf_info_for_file(elf_t *elf, const char *filename) {
    //printf("getting ELF info for [%s]\n", filename);

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
    find_dynamic(elf);
    find_got_and_plt(elf);
}

void parse_elf_info_from_self(elf_t *elf, void *address) {
    elf->fd = -1;
    elf->length = 0;
    elf->map = address;
    
    verify_elf(elf);
    
    find_basic(elf);
    find_strtab(elf);
    find_dynamic(elf);
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

static void find_dynamic(elf_t *elf) {
    elf->dynamic = 0;
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        const char *name = elf->shstrtab + s->sh_name;
        if(!strcmp(name, ".dynamic")) {
            elf->dynamic = (unsigned long *)s->sh_addr;
            break;
        }
    }
}

static void find_got_and_plt(elf_t *elf) {
    elf->got = elf->got_plt = 0;
    elf->rela_plt = elf->rela_plt_offset = elf->rela_plt_size = 0;
    elf->symtab = elf->dynsym = 0;
    elf->plt = elf->plt_size = 0;
    elf->plt_got = elf->plt_got_size = 0;
    
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        const char *name = elf->shstrtab + s->sh_name;
        if(!strcmp(name, ".got")) {
            elf->got = (unsigned long *)s->sh_addr;
        }
        if(!strcmp(name, ".got.plt")) {
            elf->got_plt = (unsigned long *)s->sh_addr;
        }
        if(!strcmp(name, ".plt")) {
            elf->plt      = (unsigned long)s->sh_addr;
            elf->plt_size = (unsigned long)s->sh_size;
        }
        if(!strcmp(name, ".rela.plt")) {
            elf->rela_plt        = (unsigned long)s->sh_addr;
            elf->rela_plt_offset = (unsigned long)s->sh_offset;
            elf->rela_plt_size   = (unsigned long)s->sh_size;
        }
        if(!strcmp(name, ".plt.got")) {
            elf->plt_got        = (unsigned long)s->sh_addr;
            elf->plt_got_size   = (unsigned long)s->sh_size;
        }
        if(!strcmp(name, ".symtab")) {
            elf->symtab = s;
        }
        if(!strcmp(name, ".dynsym")) {
            elf->dynsym = s;
        }
    }
}

int is_data_pointer(elf_t *elf, unsigned long ptr) {
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        // const char *name = elf->shstrtab + s->sh_name;
        Elf64_Xword flags = s->sh_flags;
        if ((flags & SHF_ALLOC) && (flags & SHF_EXECINSTR) == 0) {
            if (ptr >= s->sh_addr &&
                ptr <  s->sh_addr + s->sh_size) {
                return 1;
            }
        }
    }
    return 0;
}

void cleanup_elf_info(elf_t *elf) {
    munmap(elf->map, elf->length);
    close(elf->fd);
}

unsigned long get_elf_init_size(elf_t *elf) {
    for(int i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *s = &elf->sheader[i];
        const char *name = elf->shstrtab + s->sh_name;
        if(!strcmp(name, ".init")) {
            return s->sh_size;
        }
    }
    return 0;
}

// does not get base addr properly, needs elfspace
const char *get_elf_soname(elf_t *elf) {
    unsigned long *dynamic = (unsigned long *)
        ((unsigned long)elf->map + (unsigned long)elf->dynamic);
    for(unsigned long *pointer = dynamic; pointer < dynamic + 0x1000;
        pointer += 2) {

        unsigned long type = *pointer;
        if(type == DT_NULL) break;
        if(type == DT_SONAME) {
            // found it
            unsigned long dt_soname = pointer[1];
            return (const char *)dt_soname;
        }
    }
    
    // give up after searching a lot of memory, or upon finding a DT_NULL
    return 0;
}
