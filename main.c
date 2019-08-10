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
#include <ctype.h>

#include <capstone/capstone.h>

// #include "inject.h"
#include "elf_header.h"

#define TRUE 0
#define FALSE 1
#define LEN 50
#define ROSE 0xff00f0
#define BLEU 0x0008ff
#define VERT 0x23ff00
#define JAUNE 0xfbff00
#define ROUGE 0xff0000
#define MAX_LEN_OPCODES 4

// ==================================================================================================

typedef struct _option{
	bool elf_header;
	int program_header;
	int section_header;
	int op_codes;
}option;

typedef struct _arch
{
	bool CS_ARM;
	bool CS_ARM64;
	bool CS_MIPS;
	bool CS_X86;
	bool CS_PPC;         	 // PowerPC architecture
    bool CS_SPARC;          // Sparc architecture
    bool CS_SYSZ;          // SystemZ architecture
    bool CS_XCORE;
}arch;

typedef struct _bits
{
	int e_bits;
	int r_bits;
}bits;

typedef struct endianness{
	bool big_endian;
	bool little_endian;
}endianness;

// ==================================================================================================

off_t search_section(const char *section, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *ptr, int *i_sec);

int disass_sections(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt);

int  check_argvs(int argc, char **argv, option *opt);

int pack_text(Elf64_Shdr *buffer_mdata, Elf64_Ehdr *ptr, char *algo);

int disass_recursive(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt);

int prnt_data(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt);

int disass_auto(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_phdr[], Elf64_Shdr *buffer_mdata_sh[], char *file_ptr, char *sh_name_buffer[]);

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *ptr);

Elf64_Shdr *search_section_from_offt(off_t offset, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *file_ptr, size_t *i_);

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);

char  *parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[ptr->e_shnum]);

char *search_sec_frm_iter(int i, char *buffer_mdata_sh[]);

int lprnt_disassembly(cs_insn insn, csh handle);

// ==================================================================================================

int main(int argc, char *argv[]){

	option *opt;

	int check = check_argvs(argc, argv, opt);

	if (check != 0)
		exit(EXIT_FAILURE);

	char argv2_buffer[LEN];
	strncpy(argv2_buffer, argv[2], strlen(argv[2]));

	int fd = 0;
	char *file_ptr = NULL;
	Elf64_Addr entry_point = 0;
	struct stat stat_file = {0};
	Elf64_Half len_pht = 0;
	Elf64_Half len_sht = 0;
	Elf64_Phdr *ph_ptr = NULL;

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


	if (strcmp(argv[2], "-e") == 0)
	{
		get_executable_header(file_ptr, buffer_mdata_ehdr);
	}

	Elf64_Ehdr *ptr = (Elf64_Ehdr*)file_ptr;

	if (strcmp(argv[2], "-t") == 0)
	{
		// Elf64_Ehdr *ptr = (Elf64_Ehdr *)file_ptr;

		Elf64_Phdr *buffer_mdata_ph[ptr->e_phnum];

		Elf64_Shdr *buffer_mdata_sh[ptr->e_shnum];

		char *sh_name_buffer[ptr->e_shnum];


		if (!parse_phdr(ptr, buffer_mdata_ph))
		{
			if (!parse_shdr(ptr, buffer_mdata_sh))
			{
				disass_auto(ptr, buffer_mdata_ph, buffer_mdata_sh, file_ptr, sh_name_buffer);
	
			}
		}
		
	}
	

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

	size_t number_of_sections = ptr->e_phnum;

	Elf64_Phdr *buffer_mdata_ph[number_of_sections];

	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)file_ptr;

	if (strcmp(argv[2], "-p") == 0)
	{
		printf("\n");
		printf("Programm header : \n");
		printf("\n");

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
	}
	// ==================================================================================================================================================
	// ==================================================================================================================================================

	// SECTIONS HEADERS pour chaque section


		Elf64_Shdr *buffer_mdata_sh[ptr->e_shnum]; // tableau de structure contenant autant de ptr que de sections headers
		Elf64_Shdr *shstrtab_header;

		char *sh_name_buffer[ptr->e_shnum];

		shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * ptr_2->e_shstrndx));

		char *shstrndx = (char *)file_ptr + shstrtab_header->sh_offset;

		for (size_t i = 0; i < ptr->e_shnum; i++){

			buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));

			sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
		}

	if (strcmp(argv[2], "-sh") == 0)
	{

		printf("Section Header : \n");
		printf("\n");

		for (size_t i = 0; i < ptr->e_shnum; i++){

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
			printf("\tOffset : 0x%lx\n", buffer_mdata_sh[i]->sh_offset);
		}

	}

	if (strcmp(argv[2], "-a") == 0){

		for (size_t i = 0; i < ptr->e_shnum; i++)
		{
			int p = buffer_mdata_sh[i]->sh_flags & SHF_EXECINSTR;

			if (!p)
			{
				prnt_data(buffer_mdata_sh[i], file_ptr, sh_name_buffer[i], opt);
			}
			else
			{
				int success = disass_sections(buffer_mdata_sh[i], file_ptr, sh_name_buffer[i], opt);
			}

		}

	}

	else if (strcmp(argv[2], "-s") == 0 || strcmp(argv[2], "-o") == 0 )
	{
		int i_sec;

		off_t res = search_section(argv[3], buffer_mdata_sh, ptr, &i_sec);

		if (res == -1){
			printf("\n");
			printf("%s not found\n", argv[3]);
		}
		else
		{
			printf("\n");
			char *secname = sh_name_buffer[i_sec];
			printf("Section at 0x%lx (%s)\n", res, secname);
		}

		if ((buffer_mdata_sh[i_sec]->sh_flags & SHF_EXECINSTR) == 0){
			prnt_data(buffer_mdata_sh[i_sec], file_ptr, sh_name_buffer[i_sec], opt);
		}
		else
		{
			disass_sections(buffer_mdata_sh[i_sec], file_ptr, sh_name_buffer[i_sec], opt);

		}

	}

	

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

int disass_sections(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt){

	char *buffer = (unsigned char*)((void*)base_ptr + buffer_mdata_sh_p->sh_offset);

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	count = cs_disasm(handle, buffer, buffer_mdata_sh_p->sh_size, buffer_mdata_sh_p->sh_addr, 0, &insn);

	if (count <= 0){
		return -1;
	}

	printf("\n");
	printf("%ld instructions have been disassembled\n", count);
	printf("\n");

	printf("Disassembling %s\n", sh_name_buffer);
	printf("\n");

	cs_detail *detail;
	int largeur=35;

	for (size_t i = 0; i < count; i++)
	{
		printf("\033[35m"); // rose / violet
		printf("[%d bytes]", insn[i].size);

		printf("\033[34m"); // bleu
		printf(" 0x%ld ", insn[i].address);

		if (opt->op_codes == TRUE)
		{
			for (size_t j = 0; j < insn[i].size; j++)
			{
				printf("\033[33m");
				printf("%02x ", insn[i].bytes[j]);
			}

			printf("\033[37m");
			printf("-> ");

			printf("\033[32m");
			printf("%*s", largeur - insn[i].size * 3,insn[i].mnemonic);
			printf(" %s\n", insn[i].op_str);
		}

		else
		{
			printf("\033[37m");
			printf("-> ");

			printf("\033[32m");
			printf("\t%s",insn[i].mnemonic);
			printf(" %s\n", insn[i].op_str);


		}

		detail = insn[i].detail;

		if (detail->regs_read_count > 0)
		{
			for (size_t n = 0; n < detail->regs_read_count; n++)
			{
				printf("\033[37m");
				printf("\t -> %s READEN\n", cs_reg_name(handle, detail->regs_read[n]));
			}

		}

		if (detail->regs_write_count > 0)
		{
			for (size_t n = 0; n < detail->regs_write_count; n++)
			{
				printf("\033[00m");
				printf("\t\t -> %s WRITTEN\n", cs_reg_name(handle, detail->regs_write[n]));
			}
		}


	}

	return 0;
}

// ===========================================================================================================

int check_argvs(int argc, char **argv, option *opt){

	if (argc < 3)
	{
		printf("Usage : <%s> <elf> <option>\n", argv[0]);
		printf("\t-h for help\n");
		return 1;
	}
	else if (argc == 3 && strcmp(argv[2], "-h") == 0)
	{
		printf("Help : \n");
		printf("\t-a  ->  Print all the informations on a binary\n");
		printf("\t-h  ->  Print this help\n");
		printf("\t-e  -> Print the executable header only\n");
		printf("\t-sh  -> Print the section header only\n");
		printf("\t-p  -> Print the program header only\n");
		printf("\t-o <section> -> Disassemble a section with opcodes\n");
		printf("\t-s <section> -> Disassemble a section without opcodes\n");
		printf("\t-t <section> -> Linear Disassembling from the EP (EntryPoint)\n");
		return 1;
	}
	else if (argc == 3 && strcmp(argv[2], "-e") == 0)
	{
		opt->elf_header = true;
		return 0;
	}
	else if (argc == 3 && strcmp(argv[2], "-p") == 0)
	{
		opt->program_header = 1;
		return 0;
	}
	else if (argc == 3 && strcmp(argv[2], "-sh") == 0)
	{
		opt->section_header = 1;
		return 0;
	}
	else if (argc == 3 && strcmp(argv[2], "-a") == 0)
	{
		opt->section_header = FALSE;
		opt->program_header = FALSE;
		opt->elf_header = TRUE;
		return 0;
	}
	else if (strcmp(argv[2], "-t") == 0)
	{
		return 0;
	}
	
	else if (argc == 4 && strcmp(argv[2], "-o") == 0)
	{
		opt->op_codes = TRUE;
		return 0;
	}
	else if (argc == 4 && strcmp(argv[2], "-s") == 0)
	{
		return 0;
	}
	else if (argc > 4)
	{
		return 1;
	}

	else
	{
		printf("Usage : <%s> <elf> <option>\n", argv[0]);
		printf("\t-h for help\n");
		return 1;
	}
}

// ===========================================================================================================

int pack_text(Elf64_Shdr *buffer_mdata, Elf64_Ehdr *ptr,char *algo);

// ===========================================================================================================

int prnt_data(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt){

	char buffer_bytes[buffer_mdata_sh_p->sh_size];

	char *lptr = (unsigned char *) ((char *)base_ptr + buffer_mdata_sh_p->sh_offset);

	printf("Contents of the %s\n", sh_name_buffer);

	for (size_t i = 0; i < buffer_mdata_sh_p->sh_size; i++)
	{
		buffer_bytes[i] = lptr[i];
	}

	for (size_t j = 0; j < buffer_mdata_sh_p->sh_size; j++)
	{
		int t_or_not = 0;

		if (buffer_bytes[j] == '\0' && buffer_bytes[j - 1] == '\0')
		{
			printf("\\0");
			int t_or_not = 1;
		}
		else if (buffer_bytes[j] == '\0' && t_or_not != 1)
		{
			printf("\\0\n");
		}
		else if (__isascii(buffer_bytes[j]))
		{
			printf("%c", buffer_bytes[j]);
		}
		else if (isblank(buffer_bytes[j]))
		{
			printf(" ");
		}

		else
		{
			printf("%x", buffer_bytes[j]);
		}

		t_or_not = 0;

	}

	printf("\n");

	return 0;
}

// ===========================================================================================================

int disass_recursive(Elf64_Shdr *buffer_mdata_sh_p, char *base_ptr, char *sh_name_buffer, option *opt){


	return 0;
}

// ===========================================================================================================

int disass_auto(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_phdr[], Elf64_Shdr *buffer_mdata_sh[], char *file_ptr, char *sh_name_buffer[]){

	parse_sh_name(ptr, buffer_mdata_sh, sh_name_buffer);

	uint64_t v_entry_point = ptr->e_entry;

	uint64_t base_address = search_base_addr(buffer_mdata_phdr, ptr);

	off_t offset_ep = (uint64_t) ptr->e_entry - base_address;

	char *buffer = (unsigned char *)file_ptr + offset_ep;

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	size_t i = 0;

	Elf64_Shdr *buffer_mdata_sh_p = search_section_from_offt(offset_ep, buffer_mdata_sh,(Elf64_Ehdr *)file_ptr, &i);

	printf("\t %s section contains the entrypoint\n", sh_name_buffer[i]);
	printf("\n");

	count = cs_disasm(handle, buffer, buffer_mdata_sh_p->sh_size, buffer_mdata_sh_p->sh_addr, 0, &insn);

	cs_detail *detail;
	int largeur=35;

	for (size_t i = 0; i < count; i++)
	{

		// ===========================================================================================================

		/*Petit scan*/

		if (strcmp(insn[i].mnemonic, "push") == 0 && 
			strcmp(insn[i].op_str, "rbp") == 0 &&
			strcmp(insn[i+1].mnemonic, "mov") == 0 &&
			strcmp(insn[i].op_str, "rbp, rsp") == 0)
		{
			printf("\t-------------PRLOGUE DETECTED--------------\n");
		}
		else if (strcmp(insn[i].mnemonic, "ret") == 0)
		{
			printf("\t-------------EPILOGUE DETECTED--------------\n");
		}
		
		// ===========================================================================================================

		lprnt_disassembly(insn[i], handle);

	}

	return 0;
}

// ===========================================================================================================

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *ptr){

	int j = 0;
	uint64_t tab_addr[ptr->e_phnum];

	for (size_t i = 1; i < ptr->e_phnum; i++) {

		int type = buffer_mdata_phdr[i]->p_type;

		if (type == PT_LOAD)
		{
			tab_addr[j]  = buffer_mdata_phdr[i]->p_vaddr;
			j++;
		}
	}

	int base_addr = tab_addr[0];

	for (size_t i = 1; i < j; i++)
	{
		if (tab_addr[i] < base_addr){
			base_addr = tab_addr[i];
		}
	}

	return base_addr;
}

// ===========================================================================================================

Elf64_Shdr *search_section_from_offt(off_t offset, Elf64_Shdr *buffer_mdata_sh[], Elf64_Ehdr *file_ptr, size_t *_i__){

	off_t back_index = buffer_mdata_sh[0]->sh_offset;

	for (size_t i = 1; i < file_ptr->e_shnum; i++)
	{
		if ((buffer_mdata_sh[i]->sh_offset - back_index) > (buffer_mdata_sh[i]->sh_offset - offset)){
			*_i__ = i;
			return buffer_mdata_sh[i];
		}
			
	}

	return 0;
}

// ===========================================================================================================

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]){

	size_t number_of_sections = ptr->e_phnum;

	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_phnum; i++)
	{
		// (char *) buffer_mdata_ph[i] = (Elf64_Phdr *)((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));

		buffer_mdata_ph[i]  = (Elf64_Phdr *) ((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));

		// buffer_mdata_ph[i] = (Elf64_Ehdr *)ph_ptr_tmp;
	}

	return 0;
}

// ===========================================================================================================

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]){

	size_t number_of_sections = ptr->e_shnum;

	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_shnum; i++)
	{
		// (char *) buffer_mdata_ph[i] = (Elf64_Phdr *)((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));

		buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));

		// buffer_mdata_ph[i] = (Elf64_Ehdr *)ph_ptr_tmp;
	}

	return 0;
}

// ===========================================================================================================

char  *parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[ptr->e_shnum]){

	Elf64_Shdr *shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));

	const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++){

		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;

	}

	return 0;
}

// ===========================================================================================================

int lprnt_disassembly(cs_insn insn, csh handle){

		cs_detail *detail;
		int largeur=35;

		printf("\033[35m"); // rose / violet
		printf("[%d bytes]", insn.size);

		printf("\033[34m"); // bleu
		printf(" 0x%ld ", insn.address);

		size_t j;
		int k = 0;

		for (j = 0; j < insn.size && k == 0; j++)
		{		
			printf("\033[33m");
			printf("%02x ", insn.bytes[j]);
		}

			printf("\033[37m");
			printf("-> ");

			printf("\033[32m");
			printf("%*s", largeur - insn.size *3,insn.mnemonic);
			
	
			
			
			
			printf(" %s\n", insn.op_str);
			
		// printf("\033[37m");
		// printf("-> ");
		// printf("\033[32m");
		// printf("\t%s",insn[i].mnemonic);
		// printf(" %s\n", insn[i].op_str);



		detail = insn.detail;

		if (detail->regs_read_count > 0)
		{
			for (size_t n = 0; n < detail->regs_read_count; n++)
			{
				printf("\033[37m");
				printf("\t -> %s READEN\n", cs_reg_name(handle, detail->regs_read[n]));
			}

		}

		if (detail->regs_write_count > 0)
		{
			for (size_t n = 0; n < detail->regs_write_count; n++)
			{
				printf("\033[00m");
				printf("\t\t -> %s WRITTEN\n", cs_reg_name(handle, detail->regs_write[n]));
			}
		}

	return 0;
}

// ===========================================================================================================$
