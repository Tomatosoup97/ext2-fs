CC = gcc -fsanitize=address -g
CPPFLAGS = -Iinclude
CFLAGS = -Og -Wall -Wextra $(shell pkg-config --cflags fuse)
LDLIBS = $(shell pkg-config --libs fuse)

all: ext2ro ext2test

ext2ro: ext2ro.o blkio.o

blkio.o: blkio.c blkio.h
ext2ro.o: ext2ro.c ext2.h blkio.h

ext2test: ext2test.o blkio.o
ext2test.o: ext2test.c ext2.h blkio.h

clean:
	rm -f *~ *.o ext2ro ext2test

# vim: ts=8 sw=8 noet
