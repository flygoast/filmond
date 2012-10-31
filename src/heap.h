#ifndef __HEAP_H_INCLUDED__
#define __HEAP_H_INCLUDED__

typedef int (*cmp_fn)(void *, void *);
typedef void (*record_fn)(void *, int);
typedef void (*free_fn)(void *);

typedef struct heap_st {
    int         cap;
    int         len;
    void        **data;
    cmp_fn      less;
    record_fn   record;
    free_fn     ent_free;
} heap_t;

#define heap_set_less(h, l)     (h)->less = l
#define heap_set_record(h, r)   (h)->record = r
#define heap_set_free(h, f)     (h)->ent_free = f

heap_t *heap_create(void);
int heap_init(heap_t *h);
int heap_insert(heap_t *h, void *data);
void *heap_remove(heap_t *h, int k);
void heap_destroy(heap_t *h);
void heap_free(heap_t *h);

#endif /* __HEAP_H_INCLUDED__ */
