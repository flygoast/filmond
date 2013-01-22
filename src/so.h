#ifndef __SO_H_INCLUDED__
#define __SO_H_INCLUDED__

typedef struct symbol_struct {
    char    *sym_name;
    void    **sym_ptr;
    int     no_error; /* If the no_error is 1, the symbol is optional. */
} symbol_t;

extern int load_so(void **phandle, symbol_t *syms, const char *filename);
extern void unload_so(void **phandle);

#endif /* __SO_H_INCLUDED__ */
