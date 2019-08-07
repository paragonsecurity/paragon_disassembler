LIBNAME = capstone

main: main.o elf_header.o
	${CC} *.o -g -O3 -Wall -l$(LIBNAME) -o $@

elf_header: elf_header.o
	${CC} $< -O3 -Wall -o $@

%.o: %.c
	${CC} -c -g $< -o $@
