#include <string.h>
#include "allow.h"

static const char *allowed[] = {
    // All async signal safe functions from signal(7).
    // Includes everything up to and including
    // POSIX.1-2008 Technical Corrigendum 1 (2013).
    "abort",
    "accept",
    "access",
    "aio_error",
    "aio_return",
    "aio_suspend",
    "alarm",
    "bind",
    "cfgetispeed",
    "cfgetospeed",
    "cfsetispeed",
    "cfsetospeed",
    "chdir",
    "chmod",
    "chown",
    "clock_gettime",
    "close",
    "connect",
    "creat",
    "dup",
    "dup2",
    "execl",
    "execle",
    "execv",
    "execve",
    "_exit",
    "_Exit",
    "faccessat",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fchown",
    "fchownat",
    "fcntl",
    "fdatasync",
    "fexecve",
    "fork",
    "fstat",
    "fstatat",
    "fsync",
    "ftruncate",
    "futimens",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getpeername",
    "getpgrp",
    "getpid",
    "getppid",
    "getsockname",
    "getsockopt",
    "getuid",
    "kill",
    "link",
    "linkat",
    "listen",
    "lseek",
    "lstat",
    "mkdir",
    "mkdirat",
    "mkfifo",
    "mkfifoat",
    "mknod",
    "mknodat",
    "open",
    "openat",
    "pause",
    "pipe",
    "poll",
    "posix_trace_event",
    "pselect",
    "pthread_kill",
    "pthread_self",
    "pthread_sigmask",
    "raise",
    "read",
    "readlink",
    "readlinkat",
    "recv",
    "recvfrom",
    "recvmsg",
    "rename",
    "renameat",
    "rmdir",
    "select",
    "sem_post",
    "send",
    "sendmsg",
    "sendto",
    "setgid",
    "setpgid",
    "setsid",
    "setsockopt",
    "setuid",
    "shutdown",
    "sigaction",
    "sigaddset",
    "sigdelset",
    "sigemptyset",
    "sigfillset",
    "sigismember",
    "signal",
    "sigpause",
    "sigpending",
    "sigprocmask",
    "sigqueue",
    "sigset",
    "sigsuspend",
    "sleep",
    "sockatmark",
    "socket",
    "socketpair",
    "stat",
    "symlink",
    "symlinkat",
    "tcdrain",
    "tcflow",
    "tcflush",
    "tcgetattr",
    "tcgetpgrp",
    "tcsendbreak",
    "tcsetattr",
    "tcsetpgrp",
    "time",
    "timer_getoverrun",
    "timer_gettime",
    "timer_settime",
    "times",
    "umask",
    "uname",
    "unlink",
    "unlinkat",
    "utime",
    "utimensat",
    "utimes",
    "wait",
    "waitpid",
    "write",
};

int is_allowed(const char *function) {
#if 0  // linear search
    for(size_t z = 0; z < sizeof(allowed)/sizeof(*allowed); z ++) {
        if(strcmp(allowed[z], function) == 0) {
            return 1;  // allowed
        }
    }
#else  // binary search
    size_t low = 0;
    size_t high = sizeof(allowed)/sizeof(*allowed);
    size_t middle = 0;
    while(low < high) {
        middle = (low + high) / 2;

        int c = strcmp(function, allowed[middle]);
        if(c < 0) {
            high = middle;
        }
        else if(c > 0) {
            low = middle + 1;
        }   
        else {
            return 1;  // allowed
        }   
    }   
#endif
    return 0;
}
