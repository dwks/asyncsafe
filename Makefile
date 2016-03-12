CC = gcc
CFLAGS = -Wall -Wextra

.PHONY: all
all: test libasyncsafe.so

test: test.o
	$(CC) $(CFLAGS) $^ -o $@

libasyncsafe.so: safe.c elfmap.c a.s
	$(CC) $(CFLAGS) -O -shared -fPIC $^ -o $@ -ldl

clean:
	-$(RM) test test.o libasyncsafe.so
