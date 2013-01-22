#ifndef __HASH_H_INCLUDED__
#define __HASH_H_INCLUDED__

#define HASH_INIT_SLOTS     16
#define HASH_RESIZE_RATIO   1       /* (ht->count / ht->slots) */

/* assign macros */
#define HASH_SET_KEYCMP(ht, func)   (ht)->keycmp = (func)
#define HASH_SET_KEYCPY(ht, func)   (ht)->keycpy = (func)
#define HASH_SET_VALCPY(ht, func)   (ht)->valcpy = (func)
#define HASH_SET_FREE_KEY(ht, func) (ht)->free_key = (func)
#define HASH_SET_FREE_VAL(ht, func) (ht)->free_val = (func)

#define hash_clear(ht)  hash_foreach(ht, _hash_delete_foreach, ht)

#define HASH_FREE_VAL(ht, entry) do { \
    if ((ht)->free_val) \
        (ht)->free_val((entry)->val);   \
} while (0)

#define HASH_SET_VAL(ht, entry, _val_) do { \
    if ((ht)->valcpy)                       \
        entry->val = (ht)->valcpy(_val_);   \
    else                                    \
        entry->val = (_val_);               \
} while (0)

#define HASH_FREE_KEY(ht, entry) do { \
    if ((ht)->free_key)                     \
        (ht)->free_key((entry)->key);       \
} while (0)

#define HASH_SET_KEY(ht, entry, _key_) do { \
    if ((ht)->keycpy)                       \
        entry->key = (ht)->keycpy(_key_);   \
    else                                    \
        entry->key = (_key_);               \
} while (0)

#define HASH_CMP_KEYS(ht, key1, key2)   \
    (((ht)->keycmp) ? \
        (ht)->keycmp(key1, key2) : \
        (key1) == (key2))
        

typedef struct _hash_entry_t {
    void    *key;
    void    *val;

    /* next entry for linked list */
    struct _hash_entry_t *next;
} hash_entry_t;

typedef struct _hash_t {
    unsigned int    slots;
    unsigned int    count;

    /* the table */
    struct _hash_entry_t    **data;

    /* implemantation associated function pointers */
    int (*keycmp)(const void *, const void *);
    void *(*keycpy)(const void *);
    void *(*valcpy)(const void *);
    void (*free_key)(void *);
    void (*free_val)(void *);
} hash_t;

typedef struct hash_iter {
    unsigned int    pos;
    unsigned int    depth;
    hash_entry_t    *he;
    hash_t          *ht;
    void            *key;
    void            *value;
} hash_iter_t;


/* create a new hash table */
hash_t *hash_create(unsigned int slots);

/* initialise a hash table */
int hash_init(hash_t *ht, unsigned int slots);

/* destroy a hash table */
void hash_destroy(hash_t *ht);

/* free a hash table */
void hash_free(hash_t *ht);

/* insert a key/value pair into a hash table */
int hash_insert(hash_t *ht, const void *key, const void *val);

/* get a value by key */
void *hash_get_val(hash_t *ht, const void *key);

/* remove a hash value from the table */
int hash_delete(hash_t *ht, const void *key);

/* execute the provided function for each key */
int hash_foreach(hash_t *ht, 
        int (*foreach)(const hash_entry_t *he, void *userptr),
        void *userptr);

/* double the size of the hash, not enough slots */
int hash_resize(hash_t *ht);

/* copy a hash table */
hash_t *hash_dup(hash_t *ht);

/* create a new hash iterator */
hash_iter_t *hash_iter_new(hash_t *ht);

/* initialize a new hash iterator */
int hash_iter_init(hash_iter_t *iter, hash_t *ht);

/* move to the next position in the table */
int hash_iter_next(hash_iter_t *iter);

/* move to the prev position in the table */
int hash_iter_prev(hash_iter_t *iter);

/* reset the iter */
int hash_iter_reset(hash_iter_t *iter);

/* destroy a hash iterator */
void hash_iter_destroy(hash_iter_t *iter);

/* free a hash iterator */
void hash_iter_free(hash_iter_t *iter);

#endif /* __HASH_H_INCLUDED__ */
