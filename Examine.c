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
    unsigned char mem_buf[10000];
    char magic[4];             // Bytes 1, 2, 3 of the magic number (in ASCII)
    char data_encoding[20];    // Data encoding scheme of the object file
    unsigned int entry_point;  // Entry point (hexadecimal address)
    unsigned int sh_offset;    // File offset in which the section header table resides
    unsigned int sh_num;       // Number of section header entries
    unsigned int sh_size;      // Size of each section header entry
    unsigned int ph_offset;    // File offset in which the program header table resides
    unsigned int ph_num;       // Number of program header entries
    unsigned int ph_size;      // Size of each program header entry

} ELF_file_desc;

typedef struct {
    ELF_file_desc files[MAX_FILES];
    int valid_state_files[MAX_FILES];
} file_stack

typedef struct {
    char* name;
    void (*fun)(state*);
} menu_item;

void toggle_debug_mode(ELF_file_desc *file_desc) {
    if (s->debug_mode) {
        printf("Debug flag now off\n");
        s->debug_mode = 0;
    } else {
        printf("Debug flag now on\n");
        s->debug_mode = 1;
    }
}

void examine_ELF_file(file_stack* stack){
    //Get the file name from the user
    char file_name[128];
    printf("Enter ELF file name: ");
    fgets(file_name, sizeof(file_name), stdin);
    file_name[strcspn(file_name, "\n")] = 0;

    // Check if the file is already in the stack
    int found_index = -1;
    for (int i = 0; i < MAX_FILES; ++i) {
        if (strcmp(stack->files[i].file_name, file_name) == 0 && stack->valid_state_files[i] == 1) {
            found_index = i;
            break;
        }
    }

    if (found_index != -1) {
        print_elf_info(&stack->files[found_index]);
    } else {
        // File not found in the stack, find a place to store it
        int empty_index = -1;
        for (int i = 0; i < MAX_FILES; ++i) {
            if (stack->valid_state_files[i] == 0 || stack->valid_state_files[i] == -1) {
                empty_index = i;
                break;
            }
        }

        if (empty_index == -1) {
            printf("File stack is full. Cannot add more files.\n");
            return;
        }

        // Initialize a new ELF_file_desc for the file
        int fd = open(file_name, O_RDONLY);
        if (fd < 0) {
            perror("Error opening file");
            return;
        }

        struct stat st;
        if (fstat(fd, &st) < 0) {
            perror("Error getting file size");
            close(fd);
            return;
        }

        void* map_start = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (map_start == MAP_FAILED) {
            perror("Error mapping file");
            close(fd);
            return;
        }

        Elf32_Ehdr *header = (Elf32_Ehdr *)map_start;

        if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 ||
            header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3) {
            printf("Error: Not a valid ELF file\n");
            munmap(map_start, st.st_size);
            close(fd);
            return;
        }

        ELF_file_desc *file_desc = &stack->files[empty_index];
        memcpy(file_desc->magic, &header->e_ident[1], 3);
        file_desc->magic[3] = '\0';
        strcpy(file_desc->data_encoding, header->e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, little endian" : "2's complement, big endian");
        file_desc->entry_point = header->e_entry;
        file_desc->sh_offset = header->e_shoff;
        file_desc->sh_num = header->e_shnum;
        file_desc->sh_size = header->e_shentsize;
        file_desc->ph_offset = header->e_phoff;
        file_desc->ph_num = header->e_phnum;
        file_desc->ph_size = header->e_phentsize;
        strncpy(file_desc->file_name, file_name, sizeof(file_desc->file_name));

        // Mark the stack as valid
        stack->valid_state_files[empty_index] = 1;

        printf("File added to stack:\n");
        print_elf_info(file_desc);

        munmap(map_start, st.st_size);
    }
}

void print_elf_info(ELF_file_desc *file_desc) {
    printf("Magic: %.3s\n", file_desc->magic);
    printf("Data Encoding: %s\n", file_desc->data_encoding);
    printf("Entry point: 0x%x\n", file_desc->entry_point);
    printf("Section header table offset: %d\n", file_desc->sh_offset);
    printf("Number of section header entries: %d\n", file_desc->sh_num);
    printf("Size of each section header entry: %d\n", file_desc->sh_size);
    printf("Program header table offset: %d\n", file_desc->ph_offset);
    printf("Number of program header entries: %d\n", file_desc->ph_num);
    printf("Size of each program header entry: %d\n", file_desc->ph_size);
}

void not_implemented(){
    printf("not implemented yet");
}

void quit(state* s) {
    if (s->debug_mode) {
        printf("quitting\n");
    }
    exit(0);
}


int main(void) {
    state s = {0, "deep_thought", 1, {0}, 0, 0, {-1, -1}, {NULL, NULL}, {0, 0}};
    menu_item menu[] = {
        {"Toggle Debug Mode", toggle_debug_mode},
        {"Examine ELF File", examine_ELF_file},
        {"Print Section Names", not_implemented},
        {"Print Symbols", not_implemented},
        {"Check Files for Merge", not_implemented},
        {"Merge ELF Files", not_implemented},
        {"Quit", quit},
        {NULL, NULL}
    };

    while (1) {
        if (s.debug_mode) {
            fprintf(stderr, "Debug:\nunit_size: %d\nfile_name: %s\nmem_count: %zu\n", s.unit_size, s.file_name, s.mem_count);
        }

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
        if (choice == 6) while (getchar() != '\n');
    }

    return 0;
}