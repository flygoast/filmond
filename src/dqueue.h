#ifndef __DQUEUE_H_INCLUDED__
#define __DQUEUE_H_INCLUDED__

#include <stddef.h>

typedef struct dqueue_s dqueue_t;

struct dqueue_s {
    dqueue_t    *prev;
    dqueue_t    *next;
};

#define dqueue_init(q) do { \
    (q)->prev = q; \
    (q)->next = q; \
} while (0)

#define dqueue_empty(h)     (h == (h)->prev)

#define dqueue_insert_head(h, x) do { \
    (x)->next = (h)->next; \
    (x)->next->prev = x; \
    (x)->prev = h; \
    (h)->next = x; \
} while (0)

#define dqueue_insert_after dqueue_insert_head

#define dqueue_insert_tail(h, x) do { \
    (x)->prev = (h)->prev; \
    (x)->prev->next = x; \
    (x)->next = h; \
    (h)->prev = x; \
} while (0)

#define dqueue_head(h)      (h)->next
#define dqueue_last(h)      (h)->prev
#define dqueue_sentinel(h)  (h)
#define dqueue_next(q)      (q)->next
#define dqueue_prev(q)      (q)->prev

#define dqueue_remove(x) do { \
    (x)->next->prev = (x)->prev; \
    (x)->prev->next = (x)->next; \
} while (0)

/* Split the queue 'h' into two new queue.
    h: the head of old queue.
    q: the node at which the queue was splitted.
    n: the new head of the queue after 'q' node (q inclusive).
 */
#define dqueue_split(h, q, n) do { \
    (n)->prev = (h)->prev; \
    (n)->prev->next = n; \
    (n)->next = q; \
    (h)->prev = (q)->prev; \
    (h)->prev->next = h; \
    (q)->prev = n; \
} while (0)

/* Merge queue 'n' into queue 'h', the h is the sentinel. */
#define dqueue_add(h, n) do { \
    (h)->prev->next = (n)->next; \
    (h)->next->prev = (h)->prev; \
    (h)->prev = (n)->prev; \
    (h)->prev->next = h; \
} while (0)

#define dqueue_entry(q, type, link) \
    (type *)((char *)q - offsetof(type, link))

extern dqueue_t *dqueue_middle(dqueue_t *q);

extern void dqueue_sort(dqueue_t *q, 
    int (*cmp)(const dqueue_t*, const dqueue_t *));

#endif /* __DQUEUE_H_INCLUDED__ */
