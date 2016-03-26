%.o: %.c
	gcc -Wall -g -c $?

all: parser

parser: parser.o util.o
	gcc -g -o parser parser.o util.o -lpcap -lm

clean:
	rm *.o parser
