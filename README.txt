This is asyncsafe, which makes sure you only call async-signal-safe functions
from within signal handlers. It works by hijacking the PLT entries of all
functions that are not supposed to be called from signal handlers, and
printing an error message if any one is. Supports 64-bit x86_64 Linux only.

signal and sigaction are both overloaded to catch any signal handler
registration, instrumenting the handlers to automatically enable and disable
the PLT hijacking. The hijacking works by resetting PLT entries to point within
the table so that they must be resolved (as in lazy function resolving, see
ld.so(8)). The resolution function is hijacked to print an error message
(including the name of the function that was called), and defer to the real
resolution function. The PLT entries are restored when the signal handler exits
(though one could rely on the normal resolution mechanism to re-resolve them,
at a speed penalty).

The function names and PLT entries are found by parsing the ELF file of the
main executable. This will only work if the signal handler is within the main
executable, and not in a shared library.

Example:
    $ make
    gcc -Wall -Wextra  -Wno-unused-parameter test.c -o test
    gcc -Wall -Wextra  -Wno-unused-parameter test2.c -o test2
    gcc -Wall -Wextra  -O -shared -fPIC safe.c allow.c print.c elfmap.c plt.c resolve.s violation.c -o libasyncsafe.so -ldl
    $ ./test
    This handler is fine
    This handler is bad :(
    $ LD_PRELOAD=./libasyncsafe.so ./test
    This handler is fine
    asyncsafe violation! handler for signal 12 called [puts]
    This handler is bad :(

The violation message will only be printed the first time a function is called.
After that, the true function's address will be stored in the PLT.

It is also possible to link asyncsafe.so into your program directly:
    $ gcc test.c -o test -L. -lasyncsafe -Wl,-rpath=.
    $ ./test
    This handler is fine
    asyncsafe violation! handler for signal 12 called [puts]
    This handler is bad :(
    $ 

Finally, for debugging purposes or to learn how it works, turn on debugging
info:
    $ ASYNCSAFE_LOGGING=1 LD_PRELOAD=./libasyncsafe.so ./test
    getting ELF info for [/proc/16387/exe]
    asyncsafe: intercept signal 10 registration of handler 0x400726
    asyncsafe: intercept signal 12 registration of handler 0x400748
    asyncsafe on  vvv
    handler 600bf0
    allow plt entry at 600bf8 (index 1) for [raise]
    BLOCK plt entry at 600c00 (index 3) for [puts]
    allow plt entry at 600c08 (index 4) for [write]
    BLOCK plt entry at 600c10 (index 5) for [__libc_start_main]
    allow plt entry at 600c18 (index 8) for [signal]
    This handler is fine
    asyncsafe off ^^^
    handler 600bf0
    restore original plt entries
    asyncsafe on  vvv
    handler 600bf0
    allow plt entry at 600bf8 (index 1) for [raise]
    BLOCK plt entry at 600c00 (index 3) for [puts]
    allow plt entry at 600c08 (index 4) for [write]
    BLOCK plt entry at 600c10 (index 5) for [__libc_start_main]
    allow plt entry at 600c18 (index 8) for [signal]
    asyncsafe violation! handler for signal 12 called [puts]
    This handler is bad :(
    asyncsafe off ^^^
    handler 600bf0
    restore original plt entries
    $ 

For greater efficiency, compile with -DDISABLE_LOGGING to remove all print
statements at compile time (meaning the debugging will not work).

This project was created by David Williams-King in a few hours using ELF
parsing code from other projects. It is released under a BSD license. If you
like this tool and have suggestions to improve it or ideas for another tool,
please email me, dwk at cs dot columbia period edu. Thanks!
