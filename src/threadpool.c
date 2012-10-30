#include <stdio.h>
#include <stdlib.h>
#include "threadpool.h"

/* --------------- Private Prototypes ---------------------*/
static void* thread_loop(void *arg) {
    threadpool_t *pool = (threadpool_t*)arg;
    task_queue_t *entry = NULL;
    dqueue_t *qnode;

    while (!pool->exit) {
        Pthread_mutex_lock(&pool->mutex);

        while (dqueue_empty(&pool->task_queue)) {
            Pthread_cond_wait(&pool->cond, &pool->mutex);
        }
        --pool->threads_idle;
        qnode = dqueue_last(&pool->task_queue);
        dqueue_remove(qnode);
        entry = dqueue_entry(qnode, task_queue_t, queue);
        Pthread_mutex_unlock(&pool->mutex);
        if (entry) {
            entry->func(entry->arg);
            free(entry);
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
    task_queue_t *tq_entry;
    dqueue_t *qnode;
    while (!dqueue_empty(&pool->task_queue)) {
        qnode = dqueue_last(&pool->task_queue);
        dqueue_remove(qnode);
        tq_entry = dqueue_entry(qnode, task_queue_t, queue);
        free(tq_entry);
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

    dqueue_init(&pool->task_queue);
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

/* TODO: priority is not surported at present. */
int threadpool_add_task(threadpool_t *pool, 
        void (*func)(void*), void *arg, int priority) {
    int tosignal = 0;
    task_queue_t *tq = (task_queue_t*)calloc(1, sizeof(*tq));
    if (!tq) {
        return -1;
    }

    tq->func = func;
    tq->arg = arg;
    tq->priority = priority;

    Pthread_mutex_lock(&pool->mutex);
    if (dqueue_empty(&pool->task_queue)) {
        tosignal = 1;
    }
    dqueue_insert_head(&pool->task_queue, &tq->queue);
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
    if (!dqueue_empty(&pool->task_queue)) {
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
    Pthread_mutex_destroy(&pool->mutex);
    Pthread_cond_destroy(&pool->cond);
    Pthread_cond_destroy(&pool->exit_cond);
    free(pool);
    return 0;
}

#ifdef THREADPOOL_TEST_MAIN
#include <netdb.h>
#include <stdlib.h>
#include <strings.h>
static void task(void* arg) {
    int rc;
    char ipv4_addr[18];
    struct addrinfo hints, *res;
    struct sockaddr_in * temp;
    bzero(ipv4_addr, sizeof(ipv4_addr));
    bzero(&hints, sizeof(hints));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo("dummy1.flygoat.net", NULL, &hints, &res);
    if (rc != 0) {
        printf("getaddrinfo failed\n");
        return;
    }
    temp = (struct sockaddr_in *)(res->ai_addr);
    inet_ntop(AF_INET, &(temp->sin_addr.s_addr), ipv4_addr, sizeof(ipv4_addr));
    printf("%s\n", ipv4_addr);
    freeaddrinfo(res);
    return;

    printf("task:%d\ttid:%u\n", (int)arg, (int)pthread_self());
}

static void task2(void* arg) {
    int rc;
    char ipv4_addr[18];
    struct addrinfo hints, *res;
    struct sockaddr_in * temp;
    bzero(ipv4_addr, sizeof(ipv4_addr));
    bzero(&hints, sizeof(hints));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo("dummy2.flygoast.net", NULL, &hints, &res);
    if (rc != 0) {
        printf("getaddrinfo failed\n");
        return;
    }
    temp = (struct sockaddr_in *)(res->ai_addr);
    inet_ntop(AF_INET, &(temp->sin_addr.s_addr), ipv4_addr, sizeof(ipv4_addr));
    printf("%s\n", ipv4_addr);
    freeaddrinfo(res);
    return;

    printf("task:%d\ttid:%u\n", (int)arg, (int)pthread_self());
}

static void task3(void* arg) {
    int rc;
    char ipv4_addr[18];
    struct addrinfo hints, *res;
    struct sockaddr_in * temp;
    bzero(ipv4_addr, sizeof(ipv4_addr));
    bzero(&hints, sizeof(hints));

    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo("dummy3.flygoast.net", NULL, &hints, &res);
    if (rc != 0) {
        printf("getaddrinfo failed\n");
        return;
    }
    temp = (struct sockaddr_in *)(res->ai_addr);
    inet_ntop(AF_INET, &(temp->sin_addr.s_addr), ipv4_addr, sizeof(ipv4_addr));
    printf("%s\n", ipv4_addr);
    freeaddrinfo(res);
    return;

    printf("task:%d\ttid:%u\n", (int)arg, (int)pthread_self());
}

static void task4(void* arg) {
    char *name = "PATH";
    char *value = getenv(name);
    printf("%s=%s\n", name, value);
}

int main(int argc, char *argv[]) {
    int i = 1000000;
    threadpool_t *pool = threadpool_create(10, 100, 0);
    assert(pool);
    while (i > 0) {
        if (i % 3 == 0) {
            assert(threadpool_add_task(pool, task4, (void*)i, 0) == 0);
        } else if (i % 3 == 1) {
            assert(threadpool_add_task(pool, task4, (void*)i, 0) == 0);
        } else {
            assert(threadpool_add_task(pool, task4, (void*)i, 0) == 0);
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
