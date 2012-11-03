#ifndef __THREADPOOL_H_INCLUDED__
#define __THREADPOOL_H_INCLUDED__

#include <pthread.h>
#include <assert.h>
#include "heap.h"

#define THREAD_STACK_SIZE   1048576     /* 1M */

typedef struct threadpool {
    pthread_mutex_t     mutex;
    pthread_cond_t      cond;
    pthread_cond_t      exit_cond;
    pthread_cond_t      task_over_cond;
    heap_t              task_queue;
    int                 thread_stack_size;
    int                 exit;
    int                 threads_idle;
    int                 threads_num;
    int                 threads_max;
} threadpool_t;

/* ------------------- Macro wrappers ---------------------*/
#define Pthread_create(m, n, p, q) \
    assert(pthread_create(m, n, p, q) == 0)
#define Pthread_attr_init(m) \
    assert(pthread_attr_init(m) == 0)
#define Pthread_attr_setstacksize(m, n) \
    assert(pthread_attr_setstacksize(m, n) == 0)
#define Pthread_attr_setdetachstate(m, n) \
    assert(pthread_attr_setdetachstate(m, n) == 0)
#define Pthread_attr_destroy(m) \
    assert(pthread_attr_destroy(m) == 0)
#define Pthread_mutex_init(m, n) \
    assert(pthread_mutex_init(m, n) == 0)
#define Pthread_mutex_destroy(m) \
    assert(pthread_mutex_destroy(m) == 0)
#define Pthread_cond_init(m, n) \
    assert(pthread_cond_init(m, n) == 0)
#define Pthread_cond_destroy(m) \
    assert(pthread_cond_destroy(m) == 0)
#define Pthread_mutex_lock(m) \
    assert(pthread_mutex_lock(m) == 0)
#define Pthread_mutex_trylock(m) \
    assert(pthread_mutex_trylock(m) == 0)
#define Pthread_mutex_unlock(m) \
    assert(pthread_mutex_unlock(m) == 0)
#define Pthread_cond_wait(m, n) \
    assert(pthread_cond_wait(m, n) == 0)
#define Pthread_cond_signal(m) \
    assert(pthread_cond_signal(m) == 0)
#define Pthread_cond_broadcast(m) \
    assert(pthread_cond_broadcast(m) == 0)
#define Pthread_cond_timedwait(m, n, p) \
    pthread_cond_timedwait(m, n, p)

extern threadpool_t *threadpool_create(int init, int max, int stack_size);
extern int threadpool_add_task(threadpool_t *tp, 
    void (*func)(void*), void *arg, int priority);
extern void threadpool_clear_task_queue(threadpool_t *pool);
extern int threadpool_task_over(threadpool_t *pool, int block, int timeout);
extern int threadpool_destroy(threadpool_t *pool, int block, int timeout);

#endif /* __THREADPOOL_H_INCLUDED__ */
