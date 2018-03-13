.POSIX:
.SUFFIXES:

CC = gcc
CFLAGS = -Os -Wall -Werror -Wextra -pedantic
LDFLAGS = -lmsgpackc

shared: rpc.o
	$(CC) -o libserfrpc.so -shared -fPIC $(CFLAGS) rpc.c $(LDFLAGS)

static: rpc.o
	ar rcs libserfrpc.a rpc.o

rpc.o: rpc.c
	$(CC) -c -o rpc.o $(CFLAGS) rpc.c

clean:
	rm -f *.a *.o *.so
