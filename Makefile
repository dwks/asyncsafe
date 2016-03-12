CC = gcc
CFLAGS = -Wall -Wextra #-DDISABLE_LOGGING

.PHONY: all clean
all: test libasyncsafe.so

test: test.o
	$(CC) $(CFLAGS) $^ -o $@

libasyncsafe.so: safe.c allow.c print.c elfmap.c plt.c resolve.s violation.c
	$(CC) $(CFLAGS) -O -shared -fPIC $^ -o $@ -ldl

clean:
	-$(RM) test test.o libasyncsafe.so
