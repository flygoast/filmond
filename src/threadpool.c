#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include "threadpool.h"
#include "heap.h"

#define POOL_MAX_IDLE       120 /* 2 minutes */

typedef struct task_st {
    void        (*func)(void *);
    void        *arg;
    int         priority;
} task_t;


static int priority_less(void *ent1, void *ent2) {
    task_t *t1 = (task_t *)ent1;
    task_t *t2 = (task_t *)ent2;

    return (t1->priority < t2->priority) ? 1 : 0;
}

static void* thread_loop(void *arg) {
    threadpool_t *pool = (threadpool_t*)arg;
    task_t *t = NULL;
    struct timespec ts;
    struct timeval  tv;
    int ret;
    int tosignal;

    while (!pool->exit) {
        Pthread_mutex_lock(&pool->mutex);
        gettimeofday(&tv, NULL);
        ts.tv_sec = tv.tv_sec + POOL_MAX_IDLE;
        ts.tv_nsec = tv.tv_usec * 1000;

        while (pool->task_queue.len == 0) {
            ret = Pthread_cond_timedwait(&pool->cond, &pool->mutex, &ts);
            if (ret == 0) {
                if (pool->exit) {
                    goto EXIT;
                }
                break;
            } else if (ret == ETIMEDOUT) {
                goto EXIT;
            }
        }

        --pool->threads_idle;
        t = heap_remove(&pool->task_queue, 0);
        tosignal = (pool->task_queue.len == 0) ? 1 : 0;
        Pthread_mutex_unlock(&pool->mutex);

        if (tosignal) {
            Pthread_cond_broadcast(&pool->task_over_cond);
        }

        if (t) {
            t->func(t->arg);
            free(t);
        }

        Pthread_mutex_lock(&pool->mutex);
        ++pool->threads_idle;
        Pthread_mutex_unlock(&pool->mutex);
    }

    Pthread_mutex_lock(&pool->mutex);
EXIT:
    --pool->threads_idle;
    tosignal = --pool->threads_num ? 0 : 1;
    Pthread_mutex_unlock(&pool->mutex);
    if (tosignal) {
        Pthread_cond_broadcast(&pool->exit_cond);
    }
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
    assert(init > 0 && max >= init && stack_size >= 0);

    /* Allocate memory and zero all them. */
    pool = (threadpool_t *)calloc(1, sizeof(*pool));
    if (!pool) {
        return NULL;
    }

    Pthread_mutex_init(&pool->mutex, NULL);
    Pthread_cond_init(&pool->cond, NULL);
    Pthread_cond_init(&pool->exit_cond, NULL);
    Pthread_cond_init(&pool->task_over_cond, NULL);

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
    if (pool->threads_idle == 0 && pool->threads_num < pool->threads_max) {
        threadpool_thread_create(pool);
        ++pool->threads_idle;
        ++pool->threads_num;
    }
    tosignal = (pool->task_queue.len == 0)  ? 1 : 0;
    if (heap_insert(&pool->task_queue, tq) != 0) {
        free(tq);
        Pthread_mutex_unlock(&pool->mutex);
        return -1;
    }
    Pthread_mutex_unlock(&pool->mutex);
    if (tosignal) {
        Pthread_cond_broadcast(&pool->cond);
    }
    return 0;
}

void threadpool_clear_task_queue(threadpool_t *pool) {
    Pthread_mutex_lock(&pool->mutex);
    threadpool_free_task_queue(pool);
    Pthread_mutex_unlock(&pool->mutex);
}

void threadpool_exit(threadpool_t *pool) {
    Pthread_mutex_lock(&pool->mutex);
    pool->exit = 1;
    Pthread_mutex_unlock(&pool->mutex);
    Pthread_cond_broadcast(&pool->cond);
}

int threadpool_task_over(threadpool_t *pool, int block, int timeout) {
    int ret;

    Pthread_mutex_lock(&pool->mutex);
    if (pool->task_queue.len != 0) {
        if (!block) {
            Pthread_mutex_unlock(&pool->mutex);
            return -1;
        } else {
            struct timespec ts;
            struct timeval  tv;
            gettimeofday(&tv, NULL);
            ts.tv_sec = tv.tv_sec + timeout;
            ts.tv_nsec = tv.tv_usec * 1000;

            while (pool->task_queue.len != 0) {
                if (timeout == 0) {
                    Pthread_cond_wait(&pool->task_over_cond, &pool->mutex);
                } else {
                    ret = Pthread_cond_timedwait(&pool->task_over_cond, 
                        &pool->mutex, &ts);
                    if (ret == 0) {
                        Pthread_mutex_unlock(&pool->mutex);
                        return 0;
                    } else if (ret == ETIMEDOUT) {
                        Pthread_mutex_unlock(&pool->mutex);
                        return -1;
                    }
                }
            }
        }
    }
    Pthread_mutex_unlock(&pool->mutex);
    return 0;
}

int threadpool_destroy(threadpool_t *pool, int block, int timeout) {
    int ret;
    assert(pool);
    Pthread_mutex_lock(&pool->mutex);
    if (!pool->exit) {
        /* you should call `threadpool_exit' first */
        Pthread_mutex_unlock(&pool->mutex);
        return -1;
    }

    if (pool->threads_num != 0) {
        if (!block) {
            Pthread_mutex_unlock(&pool->mutex);
            return -1;
        } else {
            struct timespec ts;
            struct timeval  tv;
            gettimeofday(&tv, NULL);
            ts.tv_sec = tv.tv_sec + timeout;
            ts.tv_nsec = tv.tv_usec * 1000;

            while (pool->threads_num != 0) {
                if (timeout == 0) {
                    Pthread_cond_wait(&pool->exit_cond, &pool->mutex);
                    goto CONT;
                } else {
                    ret = Pthread_cond_timedwait(&pool->exit_cond, 
                        &pool->mutex, &ts);
                    if (ret == 0) {
                        goto CONT;
                    } else if (ret == ETIMEDOUT) {
                        Pthread_mutex_unlock(&pool->mutex);
                        return -1;
                    }
                }
            }
        }
    }
 
CONT:
    Pthread_mutex_unlock(&pool->mutex);
    heap_destroy(&pool->task_queue);
    Pthread_mutex_destroy(&pool->mutex);
    Pthread_cond_destroy(&pool->cond);
    Pthread_cond_destroy(&pool->exit_cond);
    Pthread_cond_destroy(&pool->task_over_cond);
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
    long i = 10000;
    threadpool_t *pool = threadpool_create(10, 100, 0);
    assert(pool);
    while (i > 0) {
        if (i % 3 == 0) {
            assert(threadpool_add_task(pool, task3, 
                (void*)(long)(pool->threads_num), 1000) == 0);
        } else if (i % 3 == 1) {
            assert(threadpool_add_task(pool, task2, 
                (void*)(long)(pool->threads_num), 500) == 0);
        } else {
            assert(threadpool_add_task(pool, task1, 
                (void*)(long)(pool->threads_num), 0) == 0);
        }
        i--;
    }

    while (threadpool_task_over(pool, 1, 3) != 0) {};
    threadpool_exit(pool);
    assert(threadpool_destroy(pool, 1, 3) == 0);
    exit(0);
}

#endif /* THREADPOOL_TEST_MAIN */
