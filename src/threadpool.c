#include <stdio.h>
#include <stdlib.h>
#include "threadpool.h"
#include "heap.h"

typedef struct task_st {
    void        (*func)(void *);
    void        *arg;
    int         priority;
} task_t;


/* --------------- Private Prototypes ---------------------*/
static int priority_less(void *ent1, void *ent2) {
    task_t *t1 = (task_t *)ent1;
    task_t *t2 = (task_t *)ent2;

    return (t1->priority < t2->priority) ? 1 : 0;
}

static void* thread_loop(void *arg) {
    threadpool_t *pool = (threadpool_t*)arg;
    task_t *t = NULL;

    while (!pool->exit) {
        Pthread_mutex_lock(&pool->mutex);

        while (pool->task_queue.len == 0) {
            Pthread_cond_wait(&pool->cond, &pool->mutex);
        }
        --pool->threads_idle;
        t = heap_remove(&pool->task_queue, 0);
        Pthread_mutex_unlock(&pool->mutex);
        if (t) {
            t->func(t->arg);
            free(t);
        }
        ++pool->threads_idle;
    }

    Pthread_mutex_lock(&pool->mutex);
    ++pool->threads_idle;
    if (pool->threads_idle == pool->threads_num) {
        Pthread_cond_signal(&pool->exit_cond);
    }
    Pthread_mutex_unlock(&pool->mutex);
    return NULL;
}

static void threadpool_thread_create(threadpool_t *pool) {
    pthread_t tid;
    pthread_attr_t attr;

    Pthread_attr_init(&attr);
    Pthread_attr_setstacksize(&attr, pool->thread_stack_size);
    Pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    Pthread_create(&tid, &attr, thread_loop, pool);
    Pthread_attr_destroy(&attr);
}

static void threadpool_free_task_queue(threadpool_t *pool) {
    task_t *t;
    while (pool->task_queue.len != 0) {
        t = heap_remove(&pool->task_queue, 0);
        if (t) {
            free(t);
        }
    }
}

/* --------------- threadpool API ------------------ */
threadpool_t *threadpool_create(int init, int max, int stack_size) {
    threadpool_t *pool;
    int i;
    assert(init > 0 && max > init && stack_size >= 0);

    /* Allocate memory and zero all them. */
    pool = (threadpool_t *)calloc(1, sizeof(*pool));
    if (!pool) {
        return NULL;
    }

    Pthread_mutex_init(&pool->mutex, NULL);
    Pthread_cond_init(&pool->cond, NULL);
    Pthread_cond_init(&pool->exit_cond, NULL);

    heap_init(&pool->task_queue);
    heap_set_less(&pool->task_queue, priority_less);
    pool->thread_stack_size = (stack_size == 0) ? THREAD_STACK_SIZE :
        stack_size;

    for (i = 0; i < init; ++i) {
        threadpool_thread_create(pool);
    }

    pool->threads_idle = init;
    pool->threads_num = init;
    pool->threads_max = max;
    return pool;
}

int threadpool_add_task(threadpool_t *pool, 
        void (*func)(void*), void *arg, int priority) {
    int tosignal = 0;
    task_t *tq = (task_t *)calloc(1, sizeof(*tq));
    if (!tq) {
        return -1;
    }

    tq->func = func;
    tq->arg = arg;
    tq->priority = priority;

    Pthread_mutex_lock(&pool->mutex);
    if (pool->task_queue.len == 0) {
        tosignal = 1;
    }

    if (heap_insert(&pool->task_queue, tq) != 0) {
        free(tq);
        Pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    if (tosignal) {
        Pthread_cond_broadcast(&pool->cond);
    }
    Pthread_mutex_unlock(&pool->mutex);

    return 0;
}

void threadpool_clear_task_queue(threadpool_t *pool) {
    Pthread_mutex_lock(&pool->mutex);
    threadpool_free_task_queue(pool);
    Pthread_mutex_unlock(&pool->mutex);
}

int threadpool_exit(threadpool_t *pool) {
    Pthread_mutex_lock(&pool->mutex);
    if (pool->task_queue.len != 0) {
        Pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    Pthread_mutex_unlock(&pool->mutex);
    return 0;
    /*
    while (pool->threads_idle != pool->threads_num) {
        Pthread_cond_wait(&pool->exit_cond, &pool->mutex);
    }

    Pthread_mutex_unlock(&pool->mutex);
    return 0;
    */
}

int threadpool_destroy(threadpool_t *pool) {
    assert(pool);
    Pthread_mutex_lock(&pool->mutex);
    if (!pool->exit) {
        Pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    Pthread_mutex_unlock(&pool->mutex);

    threadpool_free_task_queue(pool);
    heap_destroy(&pool->task_queue);
    Pthread_mutex_destroy(&pool->mutex);
    Pthread_cond_destroy(&pool->cond);
    Pthread_cond_destroy(&pool->exit_cond);
    free(pool);
    return 0;
}

/* gcc -g -DTHREADPOOL_TEST_MAIN threadpool.c heap.c -lpthread */
#ifdef THREADPOOL_TEST_MAIN
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>

static void task1(void* arg) {
    printf("%8lu: Priority HIGH\n", (unsigned long)arg);
    return;
}

static void task2(void* arg) {
    printf("%8lu: Priority MIDDLE\n", (unsigned long)arg);
    return;
}

static void task3(void* arg) {
    printf("%8lu: Priority LOW\n", (unsigned long)arg);
    return;
}

int main(int argc, char *argv[]) {
    long i = 1000000;
    threadpool_t *pool = threadpool_create(10, 100, 0);
    assert(pool);
    while (i > 0) {
        if (i % 3 == 0) {
            assert(threadpool_add_task(pool, task3, (void*)i, 1000) == 0);
        } else if (i % 3 == 1) {
            assert(threadpool_add_task(pool, task2, (void*)i, 500) == 0);
        } else {
            assert(threadpool_add_task(pool, task1, (void*)i, 0) == 0);
        }
        i--;
    }

    while (threadpool_exit(pool) != 0) {
        sleep(1);
    }
    threadpool_destroy(pool);
    exit(0);
}

#endif /* THREADPOOL_TEST_MAIN */
