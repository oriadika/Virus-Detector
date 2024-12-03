.SILENT: clean link compile run

all: clean compile link

link:
	gcc -g -m32 -Wall -o bubblesort bubblesort.o

compile:
	gcc -g -m32 -Wall -c -o bubblesort.o bubblesort.c

clean:
	rm -f *.o bubblesort

run:
	bubblesort