#include <stdio.h>
#include <stdlib.h>  // getenv
#include <stdarg.h>
#include <string.h>  // strcmp
#include "print.h"

#undef puts
#undef printf

int logging = 0;

void maybe_enable_logging(void) {
#ifndef DISABLE_LOGGING
    char *env = getenv("ASYNCSAFE_LOGGING");
    if(env && strcmp(env, "0")) {  // anything but "0"
        logging = 1;
    }
#endif
}

int log_printf(const char *s, ...) {
    if(!logging) return 0;
    va_list args;
    va_start(args, s);

    int r = vprintf(s, args);

    va_end(args);
    return r;
}

int log_puts(const char *s) {
    if(!logging) return EOF;
    return puts(s);
}
