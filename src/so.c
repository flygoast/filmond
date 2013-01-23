#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "log.h"
#include "so.h"

#define DLFUNC_NO_ERROR(h, v, name) do { \
    *(void **)(v) = dlsym(h, name); \
    dlerror(); \
} while (0)

#define DLFUNC(h, v, name) do { \
    *(void **)(v) = dlsym(h, name); \
    if ((error = dlerror()) != NULL) { \
        dlclose(h); \
        h = NULL; \
        return rc; \
    } \
} while (0)

int load_so(void **phandle, symbol_t *sym, const char *filename) {
    char    *error;
    int     rc = -1;
    int     i = 0;
    
    *phandle = dlopen(filename, RTLD_NOW);
    if ((error = dlerror()) != NULL) {
        boot_notify(-1, "dlopen:%s", error);
        return rc;
    }

    while (sym[i].sym_name) {
        if (sym[i].no_error) {
            DLFUNC_NO_ERROR(*phandle, sym[i].sym_ptr, sym[i].sym_name);
        } else {
            DLFUNC(*phandle, sym[i].sym_ptr, sym[i].sym_name);
        }
        ++i;
    }
    
    rc = 0;
    return rc;
}

void unload_so(void **phandle) {
    if (*phandle != NULL) {
        dlclose(*phandle);
        *phandle = NULL;
    }
}

#ifdef SO_TEST_MAIN
typedef struct so_func_struct {
    int (*handle_init)(const void *data, int proc_type);
    int (*handle_fini)(const void *data, int proc_type);
    int (*handle_task)(const void *data);
} so_func_t;

int main(int argc, char *argv[]) {
    void * handle;
    so_func_t so;
    symbol_t syms[] = {
        {"handle_init", (void **)&so.handle_init, 1},
        {"handle_fini", (void **)&so.handle_fini, 1},
        {"handle_task", (void **)&so.handle_task, 0},
        {NULL, NULL, 0}
    };

    if (argc < 2) {
        fprintf(stderr, "Invalid arguments\n");
        exit(1);
    }

    if (load_so(&handle, syms, argv[1]) < 0) {
        fprintf(stderr, "load so file failed\n");
        exit(1);
    }

    if (so.handle_init) {
        so.handle_init("handle_init", 0);
    }

    so.handle_task("handle_task");

    if (so.handle_fini) {
        so.handle_fini("handle_init", 0);
    }

    unload_so(&handle);
    exit(0);
}
#endif /* SO_TEST_MAIN */
