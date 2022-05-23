
NAME = testo

all:
	nasm -f elf64 test.asm && ld -o $(NAME) test.o && ./testo


clean:
	rm -f $(NAME) test.o
