CC = gcc
CFLAGS = -Wall -Wextra #-DDISABLE_LOGGING

.PHONY: all clean
all: test test2 libasyncsafe.so

test: test.c
	$(CC) $(CFLAGS) -Wno-unused-parameter $^ -o $@
test2: test2.c
	$(CC) $(CFLAGS) -Wno-unused-parameter $^ -o $@

libasyncsafe.so: safe.c allow.c print.c elfmap.c plt.c resolve.s violation.c
	$(CC) $(CFLAGS) -O -shared -fPIC $^ -o $@ -ldl

clean:
	-$(RM) test test2 libasyncsafe.so
