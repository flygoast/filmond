#ifndef __LOCK_H_INCLUDED__
#define __LOCK_H_INCLUDED__
#include <pthread.h>
/* You can choose your prefer lock type.
 * #define PTHREAD_LOCK_MODE
 * #define SYSVSEM_LOCK_MODE
 * #define FCNTL_LOCK_MODE
 */
#define PTHREAD_LOCK_MODE

#ifdef SYSVSEM_LOCK_MODE
typedef struct lock_struct {
    int semid;
} lock_t;

/* System V semaphore implementation of lock. */
int sysv_sem_init(const char *pathname);
int sysv_sem_lock(int semid);
int sysv_sem_unlock(int semid);
void sysv_sem_destroy(int semid);

#define LOCK_INIT(l) \
    ((((l)->semid = sysv_sem_init(NULL)) < 0) ? -1 : 0)
#define LOCK_LOCK(l)    sysv_sem_lock((l)->semid)
#define LOCK_UNLOCK(l)  sysv_sem_unlock((l)->semid)
#define LOCK_DESTROY(l) sysv_sem_destroy((l)->semid)

#elif defined(PTHREAD_LOCK_MODE)
typedef struct lock_struct {
    pthread_mutex_t mutex;
} lock_t;

int pthread_lock_init(pthread_mutex_t *mutexptr);
int pthread_do_lock(pthread_mutex_t *mutexptr);
int pthread_do_unlock(pthread_mutex_t *mutexptr);
void pthread_lock_destroy(pthread_mutex_t *mutexptr);

#define LOCK_INIT(l)    \
    ((pthread_lock_init(&((l)->mutex)) != 0) ? -1 : 0)
#define LOCK_LOCK(l)    pthread_do_lock(&((l)->mutex))
#define LOCK_UNLOCK(l)  pthread_do_unlock(&((l)->mutex))
#define LOCK_DESTROY(l) pthread_lock_destroy(&((l)->mutex))

#elif defined(FCNTL_LOCK_MODE)
typedef struct lock_struct {
    int fd;
} lock_t;

#define LOCK_RD 0
#define LOCK_WR 1
int fcntl_init(const char *pathname);
int fcntl_lock(int fd, int flag);
int fcntl_unlock(int fd);
void fcntl_destroy(int fd);


#define LOCK_INIT(l)    \
    ((((l)->fd = fcntl_init("/tmp/verben")) != -1) ? 0 : -1)
#define LOCK_LOCK(l)    fcntl_lock((l)->fd, LOCK_WR)
#define LOCK_UNLOCK(l)  fcntl_unlock((l)->fd)
#define LOCK_DESTROY(l) fcntl_destroy((l)->fd)

#endif

#endif /* __LOCK_H_INCLUDED__ */
