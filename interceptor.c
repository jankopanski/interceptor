#define _GNU_SOURCE
#include <stdio.h>
#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include "interceptor.h"

#define ELFNULL ((Elf64_Addr) 0)

struct intercept_data {
    const char *name;
    Elf64_Addr func;
};

static int (*dl_iter_global_ptr)(int (*)(struct dl_phdr_info*, size_t, void*) , void*) = NULL;

bool match_symbol_name(const char *strtab, unsigned long strtab_index, const char *symbol_name) {
    if (!strtab_index) return false;
    strtab += strtab_index;
    while (*strtab) {
        if (*strtab != *symbol_name) return false;
        ++strtab;
        ++symbol_name;
    }
    return !(*symbol_name);
}

Elf64_Addr get_function_address(const Elf64_Sym *symbol, Elf64_Addr libaddr) {
    if (!symbol->st_value) return 0;
    char info = symbol->st_info;
    Elf64_Addr funcaddr = libaddr + symbol->st_value;
    if (ELF64_ST_TYPE(info) == STT_GNU_IFUNC) {
        void *(*resolver)() = (void *(*)()) funcaddr;
        Elf64_Addr ifuncaddr = (Elf64_Addr) (*resolver)();
        return ifuncaddr;
    }
    return funcaddr;
}

unsigned long elf_hash(const unsigned char *name)
{
    unsigned long h = 0, g;
    while (*name)
    {
        h = (h << 4) + *name++;
        if ((g = h & 0xf0000000))
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

Elf64_Addr elf_lookup(const Elf32_Word *hashtab, const Elf64_Sym *symtab, const char *strtab, 
                      const char *symbol_name, Elf64_Addr libaddr) {
    Elf32_Word nbucket = hashtab[0];
    const Elf32_Word *bucket = hashtab + 2;
    const Elf32_Word *chain = bucket + nbucket;
    unsigned long x = elf_hash((const unsigned char*) symbol_name);
    unsigned long y = bucket[x % nbucket];
    Elf64_Sym symtab_entry = symtab[y];
    if (match_symbol_name(strtab, symtab_entry.st_name, symbol_name)) {
        return get_function_address(&symtab_entry, libaddr);
    }
    else {
        while (chain[y] != STN_UNDEF) {
            symtab_entry = symtab[chain[y]];
            if (match_symbol_name(strtab, symtab_entry.st_name, symbol_name)) {
                return get_function_address(&symtab_entry, libaddr);
            }
            y = chain[y];
        }
    }
    return ELFNULL;
}

unsigned gnu_hash (const unsigned char *s)
{
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h;
}

Elf64_Addr gnu_lookup(const Elf32_Word *gnuhashtab, const Elf64_Sym *symtab, const char *strtab, 
                      const char *symbol_name, Elf64_Addr libaddr) {
    unsigned nbuckets = gnuhashtab[0];
    unsigned symndx = gnuhashtab[1];
    unsigned maskwords = gnuhashtab[2];
    const Elf32_Word *bucket = gnuhashtab + 4 + 2 * maskwords;
    const Elf32_Word *chain = bucket + nbuckets;
    unsigned h1 = gnu_hash((const unsigned char*) symbol_name);
    unsigned n = bucket[h1 % nbuckets];
    if (!n) return ELFNULL;
    const Elf64_Sym *symtab_entry_ptr = &symtab[n];
    const Elf32_Word *hv = &chain[n - symndx];
    for (h1 &= ~1; 1; ++symtab_entry_ptr) {
        unsigned h2 = *hv++;
        if ((h1 == (h2 & ~1)) && match_symbol_name(strtab, symtab_entry_ptr->st_name, symbol_name)) {
            return get_function_address(symtab_entry_ptr, libaddr);
        }
        if (h2 & 1) break;
    }
    return ELFNULL;
}

Elf64_Dyn *get_dynamic(const struct dl_phdr_info *info) {
    Elf64_Dyn *dynamic = NULL;
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn*) (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    return dynamic;
}

static int lookup_handler(struct dl_phdr_info *info, size_t size, void *data) {
    struct intercept_data* idata = (struct intercept_data*) data;
    if (!*info->dlpi_name || idata->func) return 0;
    Elf64_Dyn *dynamic = get_dynamic(info);
    if (!dynamic) return 0;
    Elf64_Addr pltgot = ELFNULL;
    Elf32_Word *hashtab = NULL;
    void *gnuhashtab = NULL;
    char *strtab = NULL;
    Elf64_Sym *symtab = NULL;
    Elf64_Xword strsz = 0;
    while (dynamic->d_tag) {
        switch (dynamic->d_tag) {
            case DT_PLTGOT:
                pltgot = dynamic->d_un.d_ptr;
                break;
            case DT_HASH:
                hashtab = (Elf32_Word*) dynamic->d_un.d_ptr;
                break;
            case DT_STRTAB:
                strtab = (char *) dynamic->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab = (Elf64_Sym *) dynamic->d_un.d_ptr;
                break;
            case DT_STRSZ:
                strsz = dynamic->d_un.d_val;
                break;
            case DT_GNU_HASH:
                gnuhashtab = (void*) dynamic->d_un.d_ptr;
                break;
        }
        ++dynamic;
    }
    if (pltgot && strtab && symtab && strsz) {
        if (hashtab) {
            idata->func = elf_lookup(hashtab, symtab, strtab, idata->name, info->dlpi_addr);
        }
        else if (gnuhashtab) {
            idata->func = gnu_lookup(gnuhashtab, symtab, strtab, idata->name, info->dlpi_addr);
        }
    }
    return 0;
}

static int intercept_handler(struct dl_phdr_info *info, size_t size, void *data) {
    struct intercept_data* idata = (struct intercept_data*) data;
    Elf64_Dyn *dynamic = get_dynamic(info);
    if (!dynamic) return 0;
    Elf64_Addr pltgot = ELFNULL;
    char *strtab = NULL;
    Elf64_Sym *symtab = NULL;
    Elf64_Rela *jmprel = NULL;
    Elf64_Xword strsz = 0;
    while (dynamic->d_tag) {
        switch (dynamic->d_tag) {
            case DT_PLTGOT:
                pltgot = dynamic->d_un.d_ptr;
                break;
            case DT_STRTAB:
                strtab = (char *) dynamic->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab = (Elf64_Sym *) dynamic->d_un.d_ptr;
                break;
            case DT_STRSZ:
                strsz = dynamic->d_un.d_val;
                break;
            case DT_JMPREL:
                jmprel = (Elf64_Rela *) dynamic->d_un.d_ptr;
                break;
        }
        ++dynamic;
    }
    if (pltgot && strtab && symtab && jmprel && strsz) {
        Elf64_Xword jmprel_info = jmprel->r_info;
        while (ELF64_R_TYPE(jmprel_info) == R_X86_64_JUMP_SLOT) {
            unsigned long symtab_index = (unsigned long) ELF64_R_SYM(jmprel_info);
            unsigned long strtab_index = symtab[symtab_index].st_name;
            if (match_symbol_name(strtab, strtab_index, idata->name)) {
                Elf64_Addr *gotaddress = (Elf64_Addr *) (info->dlpi_addr + jmprel->r_offset);
                *gotaddress = idata->func;
            }
            ++jmprel;
            jmprel_info = jmprel->r_info;
        }
    }
    return 0;
}

void *intercept_function(const char *name, void *new_func) {
    static int (*dl_iter_ptr)(int (*)(struct dl_phdr_info*, size_t, void*) , void*) = dl_iterate_phdr;
    if (!dl_iter_global_ptr) dl_iter_global_ptr = dl_iter_ptr;
    struct intercept_data data;
    data.name = name;
    data.func = ELFNULL;
    (*dl_iter_ptr)(lookup_handler, &data);
    if (!data.func) return NULL;
    void *orig_func = (void*) data.func;
    data.func = (Elf64_Addr) new_func;
    (*dl_iter_ptr)(intercept_handler, &data);
    return orig_func;
}

void unintercept_function(const char *name) {
    int (*dl_iter_ptr)(int (*)(struct dl_phdr_info*, size_t, void*) , void*);
    if (dl_iter_global_ptr) dl_iter_ptr = dl_iter_global_ptr;
    else dl_iter_ptr = dl_iterate_phdr;
    struct intercept_data data;
    data.name = name;
    data.func = ELFNULL;
    (*dl_iter_ptr)(lookup_handler, &data);
    if (data.func) (*dl_iter_ptr)(intercept_handler, &data);
}