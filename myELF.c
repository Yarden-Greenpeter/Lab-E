#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>

#define MAX_FILES 2

typedef struct {
    char debug_mode;
    char file_name[128];
    unsigned char* map_start;
    Elf32_Ehdr* header;
    char magic[4];             // Bytes 1, 2, 3 of the magic number (in ASCII)
    char data_encoding[20];    // Data encoding scheme of the object file
    unsigned int entry_point;  // Entry point (hexadecimal address)
    unsigned int sh_offset;    // File offset in which the section header table resides
    unsigned int sh_num;       // Number of section header entries
    unsigned int sh_size;      // Size of each section header entry
    unsigned int ph_offset;    // File offset in which the program header table resides
    unsigned int ph_num;       // Number of program header entries
    unsigned int ph_size;      // Size of each program header entry
} state;

typedef struct {
    state files[MAX_FILES];
    int valid_state_files[MAX_FILES];
} file_stack;

typedef struct {
    char* name;
    void (*fun)(file_stack*);
} menu_item;
//---------------------------------------------------------------------------
// PART 0
void toggle_debug_mode(state *s) {
    if (s->debug_mode) {
        printf("Debug flag now off\n");
        s->debug_mode = 0;
    } else {
        printf("Debug flag now on\n");
        s->debug_mode = 1;
    }
}

void toggle_debug_mode_file_stack(file_stack *stack) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (stack->valid_state_files[i] == 1) {
            toggle_debug_mode(&stack->files[i]);
        }
    }
}

void print_elf_info(state *s) {
    printf("Magic: %.3s\n", s->magic);
    printf("Data Encoding: %s\n", s->data_encoding);
    printf("Entry point: 0x%x\n", s->entry_point);
    printf("Section header table offset: %d\n", s->sh_offset);
    printf("Number of section header entries: %d\n", s->sh_num);
    printf("Size of each section header entry: %d\n", s->sh_size);
    printf("Program header table offset: %d\n", s->ph_offset);
    printf("Number of program header entries: %d\n", s->ph_num);
    printf("Size of each program header entry: %d\n", s->ph_size);
}

int find_file_index(file_stack* stack, const char* file_name) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (strcmp(stack->files[i].file_name, file_name) == 0 && stack->valid_state_files[i] == 1) {
            return i;
        }
    }
    return -1;
}

void examine_ELF_file(file_stack* stack) {
    // Get the file name from the user
    char file_name[128];
    printf("Enter ELF file name: ");
    fgets(file_name, sizeof(file_name), stdin);
    file_name[strcspn(file_name, "\n")] = 0;

    // Check if the file is already in the stack
    int found_index = find_file_index(stack, file_name);

    if (found_index != -1) {
        print_elf_info(&stack->files[found_index]);
        return;
    }

    // Find a place to store the new file information
    int empty_index = -1;
    for (int i = 0; i < MAX_FILES; i++) {
        if (stack->valid_state_files[i] == 0) {
            empty_index = i;
            break;
        }
    }

    if (empty_index == -1) {
        printf("Cannot handle more than %d ELF files.\n", MAX_FILES);
        return;
    }

    // Open the file
    int fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return;
    }

    // Get the file size
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        perror("Failed to get file size");
        close(fd);
        return;
    }
    lseek(fd, 0, SEEK_SET);

    // Map the file into memory
    void* map_start = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_start == MAP_FAILED) {
        perror("Failed to map file");
        close(fd);
        return;
    }

    // Check if the file is an ELF file
    Elf32_Ehdr* header = (Elf32_Ehdr*)map_start;
    if (strncmp((char*)header->e_ident, ELFMAG, SELFMAG) != 0) {
        printf("Not an ELF file\n");
        munmap(map_start, file_size);
        close(fd);
        return;
    }

    // Fill the state structure with information
    state* s = &stack->files[empty_index];
    s->map_start = map_start;
    s->header = header;
    strncpy(s->file_name, file_name, sizeof(s->file_name) - 1);
    memcpy(s->magic, header->e_ident, 4);
    s->magic[4] = '\0';
    snprintf(s->data_encoding, sizeof(s->data_encoding), "%d", header->e_ident[EI_DATA]);
    s->entry_point = header->e_entry;
    s->sh_offset = header->e_shoff;
    s->sh_num = header->e_shnum;
    s->sh_size = header->e_shentsize;
    s->ph_offset = header->e_phoff;
    s->ph_num = header->e_phnum;
    s->ph_size = header->e_phentsize;

    stack->valid_state_files[empty_index] = 1;
    print_elf_info(s);
}
//---------------------------------------------------------------------------
// PART 1
// Function to print section names
void print_section_names(file_stack* stack) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (stack->valid_state_files[i] == 1) {
            state* s = &stack->files[i];
            Elf32_Shdr* sh_table = (Elf32_Shdr*)(s->map_start + s->sh_offset);
            Elf32_Shdr* shstrtab_hdr = &sh_table[s->header->e_shstrndx];
            char* shstrtab = (char*)(s->map_start + shstrtab_hdr->sh_offset);

            printf("File %s\n", s->file_name);

            printf("[index] section_name section_address section_offset section_size  section_type\n");
            
            for (unsigned int j = 0; j < s->sh_num; j++) {
                printf("[%d] %s 0x%x %d %d  %d\n", j, &shstrtab[sh_table[j].sh_name], sh_table[j].sh_addr, sh_table[j].sh_offset, sh_table[j].sh_size, sh_table[j].sh_type);
            }
        } else {
            break;  // Stop  if encounter an invalid file state
        }
    }
}
//------------------------------------------------------------------------------------
//Part 2
// Function to print symbols
void print_symbols(file_stack* stack) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (stack->valid_state_files[i] == 1) {
            state* s = &stack->files[i];
            Elf32_Shdr* sh_table = (Elf32_Shdr*)(s->map_start + s->header->e_shoff);
            Elf32_Shdr* symtab_hdr = NULL;
            Elf32_Shdr* strtab_hdr = NULL;
            Elf32_Shdr* shstrtab_hdr = &sh_table[s->header->e_shstrndx];
            char* shstrtab = (char*)(s->map_start + shstrtab_hdr->sh_offset);
            char* strtab = NULL;
            // Find the symbol table and corresponding string table section headers
            for (unsigned int j = 0; j < s->header->e_shnum; j++) {
                if (sh_table[j].sh_type == SHT_SYMTAB) {
                    symtab_hdr = &sh_table[j];
                }
                if (sh_table[j].sh_type == SHT_STRTAB) {
                    if (strcmp(&shstrtab[sh_table[j].sh_name], ".strtab") == 0) {
                        strtab_hdr = &sh_table[j];
                        strtab = (char*)(s->map_start + strtab_hdr->sh_offset);
                    }
                }
            }
            //check for an invalid symbol table, string table.
            if (symtab_hdr == NULL) {
                printf("Symbol table not found in %s\n", s->file_name);
                continue;
            }
            if (strtab_hdr == NULL || strtab == NULL) {
                printf("String table not found in %s\n", s->file_name);
                continue;
            }
            int num_symbols = symtab_hdr->sh_size / sizeof(Elf32_Sym);
            Elf32_Sym* symtab = (Elf32_Sym*)(s->map_start + symtab_hdr->sh_offset);
            //Start the printing process
            printf("File %s\n", s->file_name);
            printf("[index] value section_index section_name symbol_name\n");

            // Print each symbol
            for (int k = 0; k < num_symbols; k++) {
                const char* section_name = (symtab[k].st_shndx < s->header->e_shnum) ? &shstrtab[sh_table[symtab[k].st_shndx].sh_name] : "UNDEF";
                const char* symbol_name = (symtab[k].st_name != 0) ? &strtab[symtab[k].st_name] : "NULL";
                printf("[%d] 0x%08x %d %s %s\n", k, symtab[k].st_value, symtab[k].st_shndx, section_name, symbol_name);
            }
        } else {
            break;  // Stop if encounter an invalid file state
        }
    }
}
//------------------------------------------------------------------------------------------

void not_implemented(file_stack* stack) {
    printf("Not implemented yet\n");
}

void quit(file_stack* stack) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (stack->valid_state_files[i] == 1) {
            munmap(stack->files[i].map_start, sizeof(Elf32_Ehdr));
        }
    }
    exit(0);
}

int main(void) {
    file_stack s = {0};
    menu_item menu[] = {
        {"Toggle Debug Mode", toggle_debug_mode_file_stack},
        {"Examine ELF File", examine_ELF_file},
        {"Print Section Names", print_section_names},
        {"Print Symbols", print_symbols},
        {"Check Files for Merge", not_implemented},
        {"Merge ELF Files", not_implemented},
        {"Quit", quit},
        {NULL, NULL}
    };

    while (1) {
        printf("Choose action:\n");
        for (int i = 0; menu[i].name != NULL; i++) {
            printf("%d-%s\n", i, menu[i].name);
        }

        char input[10];
        fgets(input, sizeof(input), stdin);
        int choice = atoi(input);

        if (choice >= 0 && choice < (int)((sizeof(menu) / sizeof(menu_item)) - 1)) {
            menu[choice].fun(&s);
        } else {
            printf("Invalid choice\n");
        }
    }

    return 0;
}