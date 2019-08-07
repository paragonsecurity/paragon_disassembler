#ifndef ELF_HEADER_H
#define ELF_HEADER_H

int get_executable_header(char *file_ptr, Elf64_Ehdr *ptr_p[30]);

#endif