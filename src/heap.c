#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "heap.h"

#define HEAP_INIT_SIZE      16

static void heap_set(heap_t *h, int k, void *data) {
    h->data[k] = data;
    if (h->record) {
        h->record(data, k);
    }
}

static void heap_swap(heap_t *h, int a, int b) {
    void *tmp;
    tmp = h->data[a];
    heap_set(h, a, h->data[b]);
    heap_set(h, b, tmp);
}

static int heap_less(heap_t *h, int a, int b) {
    if (h->less) {
        return h->less(h->data[a], h->data[b]);
    } else {
        return (h->data[a] < h->data[b]) ? 1 : 0;
    }
}

static void heap_siftdown(heap_t *h, int k) {
    for ( ; ; ) {
        int p = (k - 1) / 2; /* parent */

        if (k == 0 || heap_less(h, p, k)) {
            return;
        }
        heap_swap(h, k, p);
        k = p;
    }
}

static void heap_siftup(heap_t *h, int k) {
    for ( ; ; ) {
        int l, r, s;
        l = k * 2 + 1; /* left child */
        r = k * 2 + 2; /* right child */

        /* find the smallest of the three */
        s = k;
        if (l < h->len && heap_less(h, l, s)) s = l;
        if (r < h->len && heap_less(h, r, s)) s = r;

        if (s == k) {
            return; /* statisfies the heap property */
        }

        heap_swap(h, k, s);
        k = s;
    }
}

heap_t *heap_create() {
    heap_t *h = (heap_t*)malloc(sizeof(*h));
    if (!h) return NULL;
    if (heap_init(h) != 0) {
        free(h);
        return NULL;
    }
    return h;
}

int heap_init(heap_t *h) {
    h->cap = HEAP_INIT_SIZE;
    h->len = 0;
    h->data = (void **)calloc(h->cap, sizeof(void *));
    if (!h->data) return -1;
    h->less = NULL;
    h->record = NULL;
    return 0;
}

/* heap_insert insert `data' into heap `h' according
 * to h->less.
 * 0 returned on success, otherwise -1. */
int heap_insert(heap_t *h, void *data) {
    int k;

    if (h->len >= h->cap) {
        void **ndata;
        int ncap = (h->len + 1) * 2; /* callocate twice what we need */

        ndata = realloc(h->data, sizeof(void*) * ncap);
        if (!ndata) {
            return -1;
        }
        h->data = ndata;
        h->cap = ncap;
    }
    k = h->len;
    ++h->len;
    heap_set(h, k, data);
    heap_siftdown(h, k);
    return 0;
}

void *heap_remove(heap_t *h, int k) {
    void *data;

    if (k >= h->len) {
        return NULL;
    }

    data = h->data[k];
    --h->len;
    heap_set(h, k, h->data[h->len]);
    heap_siftdown(h, k);
    heap_siftup(h, k);
    if (h->record) {
        h->record(data, -1);
    }
    return data;
}

void heap_destroy(heap_t *h) {
    void *data;
    while (h->len) {
        data = heap_remove(h, 0);
        if (h->ent_free && data) {
            h->ent_free(data);
        }
    }

    if (h->data) {
        free(h->data);
        h->data = NULL;
    }
    h->cap = 0;
    h->len = 0;
    h->less = NULL;
    h->record = NULL;
    h->ent_free = NULL;
}

void heap_free(heap_t *h) {
    heap_destroy(h);
    free(h);
}

/* gcc heap.c -DHEAP_TEST_MAIN */
#ifdef HEAP_TEST_MAIN
#include <assert.h>
#include <stdio.h>

#define TEST_NUMBER     100000

int less(void *a, void *b) {
    return (uintptr_t)a < (uintptr_t)b ? 1 : 0;
}

int main(int argc, char **argv) {
    int i;
    heap_t *h = heap_create();
    h->less = less;
    srand(time(NULL));
    for (i = 0; i < TEST_NUMBER; ++i) {
        assert(heap_insert(h, (void *)(long)(rand() % TEST_NUMBER)) == 0);
    }

    printf("Original\n==========================================\n");
    for (i = 0; i < h->len; ++i) {
        printf("%ld\n", (long)h->data[i]);
    }

    printf("Sorted\n==========================================\n");
    while (h->len != 0) {
        void *value = heap_remove(h, 0);
        printf("%ld\n", (long)value);
    }
    heap_free(h);
}
#endif /* HEAP_TEST_MAIN */
