#ifndef PRINT_H
#define PRINT_H

#ifdef DISABLE_LOGGING
    #define puts(...) (void *)0
    #define printf(...) (void *)0
#else
    #define puts(...) log_puts(__VA_ARGS__)
    #define printf(s, ...) log_printf(s, __VA_ARGS__)
#endif

void maybe_enable_logging(void);
int log_printf(const char *s, ...);
int log_puts(const char *s);

#endif
