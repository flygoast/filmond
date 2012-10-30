#include "dqueue.h"

/* find the middle queue element if the queue has odd number of 
   elements or the first element of the queue's second par otherwise. */
dqueue_t *dqueue_middle(dqueue_t *q) {
    dqueue_t *middle, *next;
    middle = dqueue_head(q);
    if (middle == dqueue_last(q)) { /* Only one entry in the queue. */
        return middle;
    }

    next = dqueue_head(q);
    for ( ; ; ) {
        middle = dqueue_next(middle);
        next = dqueue_next(next);
        if (next == dqueue_last(q)) {
            return middle;
        }

        next = dqueue_next(next);
        if (next == dqueue_last(q)) {
            return middle;
        }
    }
}

/* The stable insertion sort. */
void dqueue_sort(dqueue_t *queue,
    int (*cmp)(const dqueue_t *, const dqueue_t *)) {
    dqueue_t    *q, *prev, *next;
    q = dqueue_head(queue);
    if (q == dqueue_last(queue)) {
        return; /* Only one entry in the queue. */
    }

    /* From the second entry, start processing */
    for (q = dqueue_next(q); q != dqueue_sentinel(queue); q = next) {
        prev = dqueue_prev(q);
        next = dqueue_next(q);

        dqueue_remove(q);
        do {
            if (cmp(prev, q) <= 0) {
                break;
            }
            prev = dqueue_prev(prev);
        } while (prev != dqueue_sentinel(queue));
        dqueue_insert_after(prev, q);
    }
}

#ifdef DQUEUE_TEST_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

dqueue_t    qu;

typedef struct task_queue {
    char        *value;
    dqueue_t    queue;
} task_queue_t;

int main(int argc, char *argv[]) {
    task_queue_t *tqnode;
    dqueue_t *qt;
    dqueue_init(&qu);

    tqnode = (task_queue_t *)calloc(1, sizeof(*tqnode));
    assert(tqnode);
    tqnode->value = strdup("hello");
    dqueue_insert_head(&qu, &tqnode->queue);

    tqnode = (task_queue_t *)calloc(1, sizeof(*tqnode));
    assert(tqnode);
    tqnode->value = strdup("world");
    dqueue_insert_head(&qu, &tqnode->queue);

    tqnode = (task_queue_t *)calloc(1, sizeof(*tqnode));
    assert(tqnode);
    tqnode->value = strdup("foo");
    dqueue_insert_head(&qu, &tqnode->queue);

    tqnode = (task_queue_t *)calloc(1, sizeof(*tqnode));
    assert(tqnode);
    tqnode->value = strdup("bar");
    dqueue_insert_head(&qu, &tqnode->queue);

    while (!dqueue_empty(&qu)) {
        qt = dqueue_last(&qu);
        dqueue_remove(qt);
        tqnode = dqueue_entry(qt, task_queue_t, queue);
        printf("%s\n", tqnode->value);
        free(tqnode->value);
        free(tqnode);
    }

    exit(0);
}
#endif /* DQUEUE_TEST_MAIN */
