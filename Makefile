%.o: %.c
	gcc -Wall -g -c $?

all: parser

parser: parser.o
	gcc -g -o parser parser.o -lpcap

clean:
	rm *.o parser
