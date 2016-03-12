CC = gcc
CFLAGS = -Wall -Wextra

.PHONY: all clean
all: test libasyncsafe.so

test: test.o
	$(CC) $(CFLAGS) $^ -o $@

libasyncsafe.so: safe.c allow.c elfmap.c resolve.s
	$(CC) $(CFLAGS) -O -shared -fPIC $^ -o $@ -ldl

clean:
	-$(RM) test test.o libasyncsafe.so
