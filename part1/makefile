.SILENT: clean link compile run

all: clean compile link

link:
	gcc -g -m32 -Wall -o AntiVirus AntiVirus.o

compile:
	gcc -g -m32 -Wall -c -o AntiVirus.o AntiVirus.c

clean:
	rm -f *.o AntiVirus

run:
	AntiVirus