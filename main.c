#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libelf.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <gelf.h>
#include <stdarg.h>
#include <getopt.h>

#include <capstone/capstone.h>

// #include "inject.h"
#include "elf_header.h"

#define TRUE 0
#define FALSE 1
#define LEN 50

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec);

int disass_sections(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr);

int main(int argc, char *argv[]){

	char argv2_buffer[LEN];
	strncpy(argv2_buffer, argv[2], strlen(argv[2]));

	int fd = 0;
	char *file_ptr = NULL;
	Elf64_Addr entry_point = 0;
	struct stat stat_file = {0};
	Elf64_Half len_pht = 0;
	Elf64_Half len_sht = 0;
	Elf64_Phdr *ph_ptr = NULL;


	if (argc != 3){
		printf("Usage : %s <elf> <section>\n", argv[0]);
		exit(-1);
	}

	fd = open(argv[1], O_RDONLY);
	

	if (fstat(fd, &stat_file) != 0){
		printf("[ERROR] fstat failed\n");
		exit(-1);
	}

	file_ptr = mmap(NULL, stat_file.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	if (file_ptr == MAP_FAILED){
		printf("[ERROR] mmap failed\n");
		exit(-1);
	}

	Elf64_Ehdr *buffer_mdata_ehdr[20];

	get_executable_header(file_ptr, buffer_mdata_ehdr);

	Elf64_Ehdr *ptr = (Elf64_Ehdr*)file_ptr;

	/*
	
	Maintenant on passe aux choses sérieuses, on a un ptr sur les bytes de l'elf, on va mtn vérifier son type définit par le elf header, si c'est un elf, 
	alors on pourra vérifier son intégrité par : 
	
	typedef struct
	{
  		unsigned char e_ident[EI_NIDENT];      Magic number and other info 
 		Elf64_Half    e_type;                  Object file type 
  		Elf64_Half    e_machine;               Architecture 
		Elf64_Word    e_version;               Object file version 
 		Elf64_Addr    e_entry;                 Entry point virtual address 
  		Elf64_Off     e_phoff;                 Program header table file offset 
  		Elf64_Off     e_shoff;                 Section header table file offset 
  		Elf64_Word    e_flags;                 Processor-specific flags 
  		Elf64_Half    e_ehsize;                ELF header size in bytes 
  		Elf64_Half    e_phentsize;             Program header table entry size 
 	 	Elf64_Half    e_phnum;                 Program header table entry count 
 	 	Elf64_Half    e_shentsize;             Section header table entry size 
 	 	Elf64_Half    e_shnum;                 Section header table entry count 
  		Elf64_Half    e_shstrndx;              Section header string table index 
	}Elf64_Ehdr;
	
	typedef Elf64_Half uint16_t
	typedef Elf64_Word uint32_t
	typedef Elf64_Off uint64_t
	
	*/

	/*On check d'abord le [E_IDENT] array codé sur 16 bytes */

	// ==================================================================================================================
	
	// ============================================================================================================================================


	// Le programm header mtn

	// typedef uint64_t Elf64_Xword;

	// typedef uint32_t Elf32_Word;

	printf("\n");
	printf("Programm header : \n");
	printf("\n");

	size_t number_of_sections = ptr->e_phnum;

	Elf64_Phdr *buffer_mdata_ph[number_of_sections];

	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)file_ptr;

	for (size_t i = 0; i < ptr->e_phnum; i++)
	{
		// (char *) buffer_mdata_ph[i] = (Elf64_Phdr *)((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));

		buffer_mdata_ph[i]  = (Elf64_Phdr *) ((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));
		
		// buffer_mdata_ph[i] = (Elf64_Ehdr *)ph_ptr_tmp;

		Elf64_Phdr *ph_ptr_tmp = buffer_mdata_ph[i];

		uint32_t type = ph_ptr_tmp->p_type;

		// ======================================

		switch (buffer_mdata_ph[i]->p_type)
		{
		case PT_NULL:
			printf("\tPT_NULL");
			break;

		case PT_LOAD:
			printf("\tPT_LOAD");
			break;

		case PT_DYNAMIC:
			printf("\tPT_DYNAMIC");
			break;

		case PT_INTERP:
			printf("\tPT_INTERP");
			break;

		case PT_NOTE:
			printf("\tPT_NOTE");
			break;

		case PT_SHLIB:
			printf("\tPT_SHLIB");
			break;

		case PT_PHDR:
			printf("\tPT_PHDR");
			break;

		case PT_TLS:
			printf("\tPT_TLS");
			break;

		case PT_NUM:
			printf("\tPT_NUM");
			break;

		case PT_LOOS:
			printf("\tPT_LOOS");
			break;

		case PT_GNU_EH_FRAME:
			printf("\tPT_GNU_EH_FRAME");
			break;

		case PT_GNU_STACK:
			printf("\tPT_GNU_STACK");
			break;

		case PT_GNU_RELRO:
			printf("\tPT_GNU_RELRO");
			break;

		case PT_LOSUNW:
			printf("\tPT_LOSUNW");
			break;

		case PT_HISUNW:
			printf("\tPT_HISUNW");
			break;
		
		case PT_LOPROC:
			printf("\tPT_LOPROC");
			break;

		case PT_HIPROC:
			printf("\tPT_HIPROC");
			break;

		default:
			break;
		}

		printf(" at 0x%lx ( 0x%lx p_addr ) with ", ph_ptr_tmp->p_vaddr, ph_ptr_tmp->p_paddr);

		printf ("%c%c%c ",
		(buffer_mdata_ph[i]->p_flags & PF_R ? 'R' : ' '),
		(buffer_mdata_ph[i]->p_flags & PF_W ? 'W' : ' '),
		(buffer_mdata_ph[i]->p_flags & PF_X ? 'E' : ' '));

		printf("flags\n");
		printf("\n");
	}
	
	// ==================================================================================================================================================
	// ==================================================================================================================================================

	// SECTIONS HEADERS pour chaque section

	printf("Section Header : \n");
	printf("\n");

	Elf64_Shdr *buffer_mdata_sh[ptr->e_shnum]; // tableau de structure contenant autant de ptr que de sections headers
	Elf64_Shdr *shstrtab_header;

	char *sh_name_buffer[ptr->e_shnum];

	shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * ptr_2->e_shstrndx));

	char *shstrndx = (char *)file_ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++){

		buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;

		printf("\tSh_name : \t%s", sh_name_buffer[i]);

		switch (buffer_mdata_sh[i]->sh_type)
		{
		case SHT_NULL:
			printf("\t\t\t\t(SHT_NULL) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;
		
		case SHT_PROGBITS:
			printf("\t\t\t\t(SHT_PROGBITS) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_SYMTAB:
			printf("\t\t\t\t(SHT_SYMTAB) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_STRTAB:
			printf("\t\t\t\t(SHT_STRTAB)\n");
			break;

		case SHT_RELA:
			printf("\t\t\t(SHT_RELA) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_HASH:
			printf("\t\t\t\t(SHT_HASH) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_DYNAMIC:
			printf("\t\t\t(SHT_DYNAMIC) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_NOTE:
			printf("\t\t\t(SHT_NOTE) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_NOBITS:
			printf("\t\t\t\t(SHT_NOBITS) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_REL:
			printf("\t\t\t\t((SHT_REL) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_SHLIB:
			printf("\t\t\t\t(SHT_SHLIB) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_DYNSYM:
			printf("\t\t\t\t(SHT_DYNSYM) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_INIT_ARRAY:
			printf("\t\t\t(SHT_INIT_ARRAY) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_FINI_ARRAY:
			printf("\t\t\t(SHT_FINI_ARRAY) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_PREINIT_ARRAY:
			printf("\t\t\t\t(SHT_PREINIT_ARRAY) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_GROUP:
			printf("\t\t\t\t(SHT_GROUP) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_SYMTAB_SHNDX:
			printf("\t\t\t\t(SHT_SYMTAB_SHNDX) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_NUM:
			printf("\t\t\t\t(SHT_NUM) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_LOOS:
			printf("\t\t\t\t(SHT_LOOS) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;
		case SHT_GNU_ATTRIBUTES:
			printf("\t\t\t\t(SHT_GNU_ATTRIBUTES) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_GNU_HASH:
			printf("\t\t\t(SHT_GNU_HASH) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_GNU_LIBLIST:
			printf("\t\t\t\t(SHT_GNU_LIBLIST) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_CHECKSUM:
			printf("\t\t\t\t(SHT_CHECKSUM) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_LOSUNW:
			printf("\t\t\t\t(SHT_LOSUNW) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_SUNW_COMDAT:
			printf("\t\t\t\t(SHT_SUNW_COMDAT) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_HISUNW:
			printf("\t\t\t(SHT_HISUNW) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_LOPROC:
			printf("\t\t\t\t(SHT_LOPROC) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_HIPROC:
			printf("\t\t\t\t(SHT_HIPROC) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_LOUSER:
			printf("\t\t\t\t(SHT_LOUSER) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		case SHT_HIUSER:
			printf("\t\t\t\t(SHT_HIUSER) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;

		default:
			printf("\t\t\t([NOT RECOGNIZED]) with %c %c %c %c %c %c %c %c %c %c flags\n", 
			(buffer_mdata_sh[i]->sh_flags & SHF_WRITE ? 'W' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_ALLOC ? 'A' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'E' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_MERGE ? 'M' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_STRINGS ? 'S' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_INFO_LINK ? 'L' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_GROUP ? 'G' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_TLS ? 'T' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_COMPRESSED ? 'C' : ' '),
			(buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR ? 'L' : ' '));
			break;
		}

		printf("\tVirtual Address : 0x%lx\n", buffer_mdata_sh[i]->sh_addr);

	}

		int i_sec;

		off_t res = search_section(argv[2], buffer_mdata_sh, ptr, &i_sec);

		if (res == -1){
			printf("\n");
			printf("%s not found\n", argv[2]);
		}
		else
		{
			printf("\n");
			char *secname = sh_name_buffer[i_sec];
			printf("Section at 0x%lx (%s)\n", res, secname);
		}

		
		int success = disass_sections(buffer_mdata_sh[i_sec], file_ptr);
	

	if (munmap(file_ptr, stat_file.st_size) != 0){
		printf("[ERROR] munmap failed\n");
		exit(-1);
	}

	close(fd);
		
	exit(EXIT_SUCCESS);
}

// ===========================================================================================================

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec){
	off_t offset = 0;
	Elf64_Shdr *shstrtab_header;

	char *sh_name_buffer[ptr->e_shnum];

	shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));

	const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++){

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	
	}

	for (size_t i = 0; i < ptr->e_shnum; i++)
	{
		if (strcmp(sh_name_buffer[i], section) == 0){
			offset = buffer_mdata_sh[i]->sh_offset;
			*i_sec = i;
			return offset;
		}
		
	}

	return -1;
}

// ===========================================================================================================

int disass_sections(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr){

	char *buffer = (unsigned char*)((void*)base_ptr + buffer_mdata_sh_p->sh_offset);

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	count = cs_disasm(handle, buffer, buffer_mdata_sh_p->sh_size, buffer_mdata_sh_p->sh_addr, 0, &insn);

	if (count <= 0){
		return -1;
	}

	printf("%ld instructions have been disassembled\n", count);
	printf("\n");

	for (size_t i = 0; i < count; i++)
	{
		printf("[%d bytes] 0x%ld -> %s %s\n", insn[i].size, insn[i].address, insn[i].mnemonic, insn[i].op_str);
	}
	
	

	return 0;
}

// ===========================================================================================================