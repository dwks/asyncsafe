#include <string.h>
#include "allow.h"

static const char *allowed[] = {
    "write"
};

int is_allowed(const char *function) {
#if 1  // linear search
    for(size_t z = 0; z < sizeof(allowed)/sizeof(*allowed); z ++) {
        if(strcmp(allowed[z], function) == 0) {
            return 1;  // allowed
        }
    }
#endif
    return 0;
}
