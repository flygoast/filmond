#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "lock.h"
#include "log.h"

#define SCREEN_COLS     80
#define CONTENT_COLS    65

#define OK_STATUS \
    (isatty(STDOUT_FILENO) ? \
        ("\033[1m[\033[32m  OK  \033[37m]\033[m") : \
        ("[  OK  ]"))
#define FAILED_STATUS \
    (isatty(STDOUT_FILENO) ? \
        ("\033[1m[\033[31mFAILED\033[37m]\033[m") : \
        ("[FAILED]"))

#define LOG_BUFFER_SIZE     (8192)
#define LOG_MAX_SIZE        (1024 * 1024 * 1024)
#define LOG_MAX_NUMBER      100

#define LOG_PATH_MAX        1024 /* TODO */

static char *log_level_text[] = {
    "FATAL", 
    "ERROR", 
    "WARNING", 
    "NOTICE", 
    "DEBUG" 
};

static lock_t lock;
static char *log_buffer = MAP_FAILED;
static int log_has_init;
static int log_level;
static int log_size;
static int log_number;
static int log_multi;
struct log_multi_struct {
    int     fd;
    char    path[LOG_PATH_MAX];
} log_files[LOG_LEVEL_DEBUG + 1];

static int log_rotate(int fd, const char *path) {
    char    temppath[LOG_PATH_MAX];
    char    temppath2[LOG_PATH_MAX];
    int     i;
    struct  stat st;

    if (fstat(fd, &st)) {
        return 0;
    }

    if (st.st_size > log_size) {
        for (i = 0; i < log_number; i++) {
            snprintf(temppath, LOG_PATH_MAX, "%s.%d", path, i);
            if (access(temppath, F_OK)) {
                /* the tempfile does not exist */
                rename(path, temppath);
                return 0;
            }
        }

        /* log file number gets maximum limit */
        for (i = 1; i < log_number; i++) {
            snprintf(temppath, LOG_PATH_MAX, "%s.%d", path, i);
            snprintf(temppath2, LOG_PATH_MAX,
                "%s.%d", path, i - 1);
            rename(temppath, temppath2);
        }
    }
    return -1;
}

int log_init(const char *dir, const char *filename, int level, int size, 
        int n, int multi) {
    assert(filename && dir);
    assert(level >= LOG_LEVEL_FATAL && level <= LOG_LEVEL_ALL);
    assert(size >= 0 && size <= LOG_MAX_SIZE);
    assert(n > 0 && n <= LOG_MAX_NUMBER);


    if (log_has_init) {
        return -1;
    }

    if (access(dir, W_OK)) {
        fprintf(stderr, "access log dir \"%s\" failed:%s\n", dir,
            strerror(errno));
        return -1;
    }

    log_level = level;
    log_size = size;
    log_number = n;
    log_multi = !!multi;

    if (log_multi) {
        int i;
        for (i = 0; i <= LOG_LEVEL_DEBUG; ++i) {
            log_files[i].fd = -1;
            strcpy(log_files[i].path, dir);
            if (log_files[i].path[strlen(dir)] != '/') {
                strcat(log_files[i].path, "/");
            }
            strcat(log_files[i].path, filename);
            strcat(log_files[i].path, "_");
            strcat(log_files[i].path, log_level_text[i]);
        }
    } else {
        log_files[0].fd = -1;
        strcpy(log_files[0].path, dir);
        if (log_files[0].path[strlen(dir)] != '/') {
            strcat(log_files[0].path, "/");
        }
        strcat(log_files[0].path, filename);
    }

    if (log_buffer == MAP_FAILED) {
        log_buffer = mmap(0, LOG_BUFFER_SIZE, PROT_WRITE | PROT_READ,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (log_buffer == MAP_FAILED) {
            fprintf(stderr, "mmap log buffer failed:%s\n", 
                strerror(errno));
            return -1;
        }
    }

    log_has_init = 1;

    LOCK_INIT(&lock);
    return 0;
}

void boot_notify(int ok, const char *fmt, ...) {
    va_list     ap;
    int         n;

    if (log_buffer == MAP_FAILED) {
        log_buffer = mmap(0, LOG_BUFFER_SIZE, PROT_WRITE | PROT_READ, 
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (log_buffer == MAP_FAILED) {
            fprintf(stderr, "mmap log buffer failed: %s\n", 
                strerror(errno));
        }
    }

    va_start(ap, fmt);
    n = vsnprintf(log_buffer, SCREEN_COLS, fmt, ap);
    va_end(ap);

    if (n > CONTENT_COLS) {
        printf("%-*.*s%s%s\n", CONTENT_COLS - 5, CONTENT_COLS - 5, 
            log_buffer, " ... ", ok == 0 ? OK_STATUS : FAILED_STATUS);
    } else {
        printf("%-*.*s%s\n", CONTENT_COLS, CONTENT_COLS, log_buffer, 
            ok == 0 ? OK_STATUS : FAILED_STATUS);
    }
}

void log_close() {
    int i;
    if (log_multi) {
        for (i = 0; i <= LOG_LEVEL_DEBUG; ++i) {
            if (log_files[i].fd != -1) {
                close(log_files[i].fd);
                log_files[i].fd = -1;
            }
        }
    } else {
        close(log_files[0].fd);
        log_files[0].fd = -1;
    }
    log_has_init = 0;
}

void log_write(int level, const char *fmt, ...) {
    struct tm   tm;
    int         pos;
    int         end;
    int         status;
    va_list     ap;
    time_t      now;
    int         index;

    if (level > log_level) {
        return;
    }

    LOCK_LOCK(&lock);
    if (log_buffer == MAP_FAILED) {
        log_buffer = mmap(0, LOG_BUFFER_SIZE, PROT_WRITE | PROT_READ, 
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (log_buffer == MAP_FAILED) {
            fprintf(stderr, "mmap log buffer failed: %s\n", 
                strerror(errno));
            return;
        }
    }

    now = time(NULL);
    localtime_r(&now, &tm);
    /*
     * we assume the string length would not beyond the buffer boundary
     */
    pos = sprintf(log_buffer, 
        "[%04d/%02d/%02d-%02d:%02d:%02d][%06d][%s]", 
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, 
        tm.tm_hour, tm.tm_min, tm.tm_sec, getpid(), 
        log_level_text[level]);

    va_start(ap, fmt);
    end = vsnprintf(log_buffer + pos, LOG_BUFFER_SIZE - pos, fmt, ap);
    va_end(ap);

    if (end < LOG_BUFFER_SIZE - pos) {
        log_buffer[end + pos] = '\n';
    } else {
        log_buffer[LOG_BUFFER_SIZE - 2] = '\n';
        end = LOG_BUFFER_SIZE - pos - 1;
    }

    index = log_multi ? level : 0;

    if ((log_files[index].fd != -1 && 
            log_rotate(log_files[index].fd, 
                (const char*)log_files[index].path) == 0)) {
        close(log_files[index].fd);
        log_files[index].fd = -1;
    }

    if (log_files[index].fd == -1) {
        log_files[index].fd = open(log_files[index].path, 
            O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (log_files[index].fd < 0) {
            fprintf(stderr, "open log file %s failed: %s\n", 
                log_files[index].path, strerror(errno));
        }

        status = fcntl(log_files[index].fd, F_GETFD, 0);
        status |= FD_CLOEXEC;
        fcntl(log_files[index].fd, F_SETFD, status);
    }

    if (write(log_files[index].fd, log_buffer, end + pos + 1)
            != end + pos + 1) {
        fprintf(stderr, "write log to file %s failed: %s\n", 
            log_files[index].path, strerror(errno));
    }
    LOCK_UNLOCK(&lock);
}

#ifdef TEST_LOG_MAIN

int main(int argc, char *argv[]) {
    int i = 0;
    BOOT_OK("This is ok:%s", "we'll continue");
    BOOT_OK("This is ok:%s", "This is a very long message which will extended the limit of the screen");
    INIT_LOG("./log", "test.log", LOG_LEVEL_ALL);
    BOOT_OK("initialize log file");

    srand(time(NULL));
    while (1) {
        log_write(rand() % (LOG_LEVEL_DEBUG + 1), 
            "[%s:%d]%s:%d", __FILE__, __LINE__,
            "Just a test log", i++);
    }

    exit(0);
}
#endif /* TEST_LOG_MAIN */
