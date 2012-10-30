#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>
#include "lock.h"

#if defined(PTHREAD_LOCK_MODE)
/* Lock implementation based on pthread mutex. */
int pthread_lock_init(pthread_mutex_t *mutexptr) {
    pthread_mutexattr_t     mattr;

    if (pthread_mutexattr_init(&mattr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_setpshared(&mattr, 
            PTHREAD_PROCESS_SHARED) != 0) {
        pthread_mutexattr_destroy(&mattr);
        return -1;
    }

    if (pthread_mutex_init(mutexptr, &mattr) != 0) {
        pthread_mutexattr_destroy(&mattr);
        return -1;
    }
    pthread_mutexattr_destroy(&mattr);
    return 0;
}

int pthread_do_lock(pthread_mutex_t *mutexptr) {
    if (pthread_mutex_lock(mutexptr) != 0) {
        return -1;
    }
    return 0;
}

int pthread_do_unlock(pthread_mutex_t *mutexptr) {
    if (pthread_mutex_unlock(mutexptr) != 0) {
        return -1;
    }
    return 0;
}

void pthread_lock_destroy(pthread_mutex_t *mutexptr) {
    pthread_mutex_destroy(mutexptr);
}


#elif defined(SYSVSEM_LOCK_MODE)
/* Lock implementation based on System V semaphore. */
#define PROJ_ID_MAGIC   0xCD
union semun{ 
    int val;                  /* value for SETVAL */
    struct semid_ds *buf;     /* buffer for IPC_STAT, IPC_SET */
    unsigned short *array;    /* array for GETALL, SETALL */
                              /* Linux specific part: */
    struct seminfo *__buf;    /* buffer for IPC_INFO */
}; 

int sysv_sem_init(const char *pathname) {
    int rc;
    union semun arg;
    int semid;
    int oflag = IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR;
    key_t key = IPC_PRIVATE;

    if (pathname) {
        key = ftok(pathname, PROJ_ID_MAGIC);
        if (key < 0) {
            return -1;
        }
    }

    if ((semid = semget(key, 1, oflag)) < 0) {
        return -1;
    }

    arg.val = 1;
    do {
        rc = semctl(semid, 0, SETVAL, arg);
    } while (rc < 0);

    if (rc < 0) {
        do {
            semctl(semid, 0, IPC_RMID, 0);
        } while (rc < 0 && errno == EINTR);
        return -1;
    }

    return semid;
}

int sysv_sem_lock(int semid) {
    int rc;
    struct sembuf op;
    op.sem_num = 0;
    op.sem_op = -1;
    op.sem_flg = SEM_UNDO;

    rc = semop(semid, &op, 1);
    return rc;
}

int sysv_sem_unlock(int semid) {
    int rc;
    struct sembuf op;
    op.sem_num = 0;
    op.sem_op = 1;
    op.sem_flg = SEM_UNDO;

    rc = semop(semid, &op, 1);
    return rc;
}

void sysv_sem_destroy(int semid) {
    int rc;
    do {
        rc = semctl(semid, 0, IPC_RMID, 0);
    } while (rc < 0 && errno == EINTR);
}

#elif defined(FCNTL_LOCK_MODE)
/* Lock implemention based on 'fcntl'. */
#ifndef MAXPATHLEN
#   ifdef PAHT_MAX
#       define MAXPATHLEN PATH_MAX
#   elif defined(_POSIX_PATH_MAX)
#       define MAXPATHLEN _POSIX_PATH_MAX
#   else
#       define MAXPATHLEN   256
#   endif
#endif

static int strxcat(char *dst, const char *src, int size) {
    int dst_len = strlen(dst);
    int src_len = strlen(src);
    if (dst_len + src_len < size) {
        memcpy(dst + dst_len, src, src_len + 1);
        return 0;
    } else {
        memcpy(dst + dst_len, src, (size - 1) - dst_len);
        dst[size - 1] = '\0';
        return -1;
    }
}

int fcntl_init(const char *pathname) {
    char s[MAXPATHLEN];
    int fd;
    strncpy(s, pathname, MAXPATHLEN - 1);
    strxcat(s, ".sem.XXXXXX", MAXPATHLEN);
    fd = mkstemp(s);
    if (fd < 0) {
        return -1;
    }
    unlink(s);
    return fd;
}

int fcntl_lock(int fd, int flag) {
    int rc;
    struct flock l;
    l.l_whence  = SEEK_SET;
    l.l_start   = 0;
    l.l_len     = 0;
    l.l_pid     = 0;
    if (flag == LOCK_RD) {
        l.l_type = F_RDLCK;
    } else {
        l.l_type = F_WRLCK;
    }

    rc = fcntl(fd, F_SETLKW, &l);
    return rc;
}

int fcntl_unlock(int fd) {
    int rc;
    struct flock l;
    l.l_whence = SEEK_SET;
    l.l_start = 0;
    l.l_len = 0;
    l.l_pid = 0;
    l.l_type = F_UNLCK;

    rc = fcntl(fd, F_SETLKW, &l);
    return rc;
}

void fcntl_destroy(int fd) {
    close(fd);
}
#endif
