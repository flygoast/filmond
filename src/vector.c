#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "vector.h"

vector_t *vector_new(unsigned int slots, unsigned int size) {
    vector_t *vec = (vector_t*)calloc(1, sizeof(*vec));
    if (!vec) return NULL;
    if (vector_init(vec, slots, size) < 0) {
        free(vec);
        return NULL;
    }

    return vec;
}

int vector_init(vector_t *vec, unsigned int slots, unsigned int size) {
    if (!slots) slots = 16;
    vec->slots = slots;

    vec->size = size;
    vec->count = 0;

    vec->data = calloc(1, vec->slots * vec->size);
    if (!vec->data) {
        return -1;
    }
    return 0;
}
    
int vector_push(vector_t *vec, void *data) {
    if (vec->count == (vec->slots - 1)) {
        if (vector_resize(vec) < 0) {
            return -1;
        }
    }
    return vector_set_at(vec, vec->count, data);
}

int vector_set_at(vector_t *vec, unsigned int index, void *data) {
    while (index >= vec->slots) {
        /* resize until our table is big enough. */
        if (vector_resize(vec) < 0) {
            return -1;
        }
    }

    memcpy((char *)vec->data + (index * vec->size), data, vec->size);
    ++vec->count;
    return 0;
}

void *vector_get_at(vector_t *vec, unsigned int index) {
    if (index >= vec->slots) return NULL;

    return (char *)vec->data + (index * vec->size);
}

/* double the number of the slots available to a vector */
int vector_resize(vector_t *vec) {
    void *temp;

    temp = realloc(vec->data, vec->slots * 2 * vec->size);
    if (!temp) {
        return -1;
    }

    vec->data = temp;
    vec->slots *= 2;
    return 0;
}


/* clear the vector */
void vector_clear(vector_t *vec) {
    memset((char *)vec, 0, vec->slots * vec->size);
}

/* destroy the vector */
void vector_destroy(vector_t *vec) {
    if (vec->data) free(vec->data);
    vec->slots = 0;
    vec->count = 0;
    vec->size = 0;
    vec->data = NULL;
}

void vector_free(vector_t *vec) {
    vector_destroy(vec);
    free(vec);
}

vector_iter_t *vector_iter_new(vector_t *vec) {
    vector_iter_t *iter;

    iter = (vector_iter_t *)calloc(1, sizeof(*iter));
    if (!iter) {
        return NULL;
    }

    if (vector_iter_init(iter, vec) != 0) {
        free(iter);
        return NULL;
    }

    return iter;
}

int vector_iter_init(vector_iter_t *iter, vector_t *vec) {
    iter->pos = 0;
    iter->vec = vec;
    iter->data = NULL;

    return vector_iter_next(iter);
}

int vector_iter_next(vector_iter_t *iter) {
    if (iter->vec->count == 0) {
        return -1;
    }

    if (iter->pos == (iter->vec->count - 1)) {
        return -1;
    }

    if (!iter->data && !iter->pos) {
        /* run for the first time */
        iter->data = iter->vec->data;
        return 0;
    } else {
        ++iter->pos;
        iter->data = (char *)iter->vec->data + 
            (iter->pos * iter->vec->size);
        return 0;
    }
}

int vector_iter_prev(vector_iter_t *iter) {
    if (vector_iter_begin(iter)) {
        return -1;
    }

    --iter->pos;
    iter->data = (char *)iter->vec->data + (iter->pos * iter->vec->size);
    return 0;
}

void vector_iter_destroy(vector_iter_t *iter) {
    iter->pos = 0;
    iter->data = NULL;
    iter->vec = NULL;
}

void vector_iter_free(vector_iter_t *iter) {
    vector_iter_destroy(iter);
    free(iter);
}

int vector_iter_begin(vector_iter_t *iter) {
    return (!iter->pos) ? 1 : 0;
}

int vector_iter_end(vector_iter_t *iter) {
    return (iter->pos == iter->vec->count - 1) ? 1 : 0;
}

void vector_iter_reset(vector_iter_t *iter) {
    vector_t *tmp = iter->vec;
    vector_iter_destroy(iter);
    vector_iter_init(iter, tmp);
}

#ifdef VECTOR_TEST_MAIN
#define COUNT       1000000
int main(int argc, char **argv) {
    int i = 0;
    int *value;
    vector_t *vec = vector_new(32, sizeof(int));
    for (i = 0; i < COUNT; ++i) {
        vector_push(vec, &i);
    }

    for (i = 0; i < COUNT; ++i) {
        value = vector_get_at(vec, i);
        assert(*value == i);
    }

    vector_iter_t *iter = vector_iter_new(vec);

    do {
        printf("%ld\n", (long)iter->data);
    } while (vector_iter_next(iter) == 0);

    vector_iter_free(iter);

    vector_free(vec);
    exit(0);
}
#endif /* VECTOR_TEST_MAIN */
