# make all
all:
	gcc client.c -ansi -pedantic -Wall -std=c17 -o nouclient

# make clean
clean:
	-rm -fr nouclient



