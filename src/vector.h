#ifndef __VECTOR_H_INCLUDED__
#define __VECTOR_H_INCLUDED__

typedef struct vector_t {
    unsigned    int count;
    unsigned    int slots;
    unsigned    int size;
    void        *data;
} vector_t;

typedef struct vector_iter {
    unsigned int    pos;
    vector_t        *vec;
    void            *data;
} vector_iter_t;

/* create a new vector */
vector_t *vector_new(unsigned int slots, unsigned int size);

/* initialize an allocated vector */
int vector_init(vector_t *v, unsigned int slots, unsigned int size);

/* append a value to the vector */
int vector_push(vector_t *v, void *data);

/* set a value at some position */
int vector_set_at(vector_t *v, unsigned int index, void *data);

/* get the value at some position */
void *vector_get_at(vector_t *v, unsigned int index); 

/* clear the whole vector */
void vector_clear(vector_t *v);

/* resize the vector */
int vector_resize(vector_t *v);

/* destory the vector */
void vector_destroy(vector_t *v);

/* free the vector */
void vector_free(vector_t *v);

/* create a new vector iterator */
vector_iter_t *vector_iter_new(vector_t *vec);

/* initialize a new vector iterator */
int vector_iter_init(vector_iter_t *iter, vector_t *vec);

/* move to next position in the table */
int vector_iter_next(vector_iter_t *iter);

/* move to prev position in the table */
int vector_iter_prev(vector_iter_t *iter);

/* check if we are at the beginning */
int vector_iter_begin(vector_iter_t *iter);

/* check if we are at the end */
int vector_iter_end(vector_iter_t *iter);

/* reset the position of the vector iterator. */
void vector_iter_reset(vector_iter_t *iter);

/* destroy a vector iter */
void vector_iter_destroy(vector_iter_t *iter);

/* free a vector iter */
void vector_iter_free(vector_iter_t *iter);

#endif /* __VECTOR_H_INCLUDED__ */
