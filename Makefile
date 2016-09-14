CC = gcc
CFLAGS = -std=gnu99 -Wall -Wextra -Wno-unused-result -Wl,-z,lazy #-DDISABLE_LOGGING

.PHONY: all clean
all: test test2 testlink libasyncsafe.so

test: test.c
	$(CC) $(CFLAGS) -Wno-unused-parameter $^ -o $@
test2: test2.c
	$(CC) $(CFLAGS) -Wno-unused-parameter $^ -o $@
testlink: test.c libasyncsafe.so
	$(CC) $(CFLAGS) -Wno-unused-parameter $^ -o $@ -lasyncsafe -L. -Wl,-rpath,.

libasyncsafe.so: safe.c allow.c print.c elfmap.c plt.c resolve.s violation.c
	$(CC) $(CFLAGS) -O -shared -fPIC $^ -o $@ -ldl

clean:
	-$(RM) test test2 testlink libasyncsafe.so
