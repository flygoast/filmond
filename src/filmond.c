#define _XOPEN_SOURCE 500 
#define _GNU_SOURCE
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/resource.h>
#include <signal.h>
#include <sys/inotify.h>
#include <curl/curl.h>
#include "inotifytools/inotify.h"
#include "inotifytools/inotifytools.h"
#include "threadpool.h"
#include "conf.h"
#include "log.h"
#include "md5.h"

#define FILMON_VERSION      "0.9.0"
#define KEY_SIZE            33
#define HTTP_BODY_SIZE      8192
#define MAX_PATH_LEN        4096
#define MAX_FILE_NAME_LEN   128
#define KEY_LEN             (33 + 32)
/* contain the space for file size */
#define MD5_BUF_SIZE        (KEY_LEN * 50)
#define HOSTNAME_LEN        128
#define MONI_EVENTS         (\
    IN_ATTRIB               |\
    IN_CLOSE_WRITE          |\
    IN_MOVED_FROM           |\
    IN_MOVED_TO             |\
    IN_CREATE               |\
    IN_DELETE               |\
    IN_DELETE_SELF          |\
    IN_DONT_FOLLOW          |\
    IN_ONLYDIR              )

#define RESPONSE_LIMIT      1024
#define MIN(a, b)           ((a) < (b) ? (a) : (b))

#define ACTION_ADD_OR_MOD       'a'
#define ACTION_DEL              'd'

char *g_hostname;
char *exten[30];
char *exclude[30];
struct curl_slist *list;
int  g_hostname_size;
threadpool_t *g_pool;
int count;
char md5_buf[MD5_BUF_SIZE];

struct global_conf_st {
    char    *moni_dir;
    char    *exclude;
    char    *valid_exten;
    char    *report_addr;
    char    *report_host;
    int     thread_init;
    int     thread_max;
    int     thread_stack;
    char    *log_dir;
    char    *log_name;
    int     log_level;
    int     log_size;
    int     log_num;
    int     log_multi;
} global_conf;

typedef struct task_item {
    int     action;
    char    *md5;
} task_item;

static size_t curl_write_cb(char *ptr, size_t size, 
        size_t count, void *buf) {
    size_t n = MIN((size * count), RESPONSE_LIMIT - strlen((char *)buf));
    memcpy((char *)buf + strlen((char *)buf), ptr, n);
    return n;
}

/* Task callback called by thread in threadpool. */
static void submit_file_info(void *arg) {
    task_item *item = (task_item *)arg;
    char response[RESPONSE_LIMIT] = {};  /* Must clear data with '0' */
    CURL *curl;
    CURLcode res;
    char field[HTTP_BODY_SIZE];
    long rc = 0;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        ERROR_LOG("curl_easy_init failed");
        goto end;
    }

    curl_easy_setopt(curl, CURLOPT_URL, global_conf.report_addr);
    snprintf(field, HTTP_BODY_SIZE, "action=%c&host=%s&md5s=%s",
            item->action, g_hostname, item->md5);
    DEBUG_LOG("body:%s", field);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, field);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);
    if (res != 0) {
        fprintf(stderr, "curl_easy_perform failed:%s\n", 
                curl_easy_strerror(res));
        ERROR_LOG("curl_easy_perform failed:%s", curl_easy_strerror(res));
        goto release;
    }

    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rc);
    if (res != 0) {
        fprintf(stderr, "curl_easy_getinfo failed:%s\n", 
                curl_easy_strerror(res));
        ERROR_LOG("curl_easy_getinfo failed:%s", curl_easy_strerror(res));
        goto release;
    }

    if (rc != 200) {
        fprintf(stderr, "submit failed: HTTP CODE: %ld\n", rc);
        ERROR_LOG("submit failed: HTTP CODE: %ld", rc);
        goto release;
    }

    response[RESPONSE_LIMIT - 1] = '\0';

    if (strcmp(response, "success") == 0) {
        printf("submit success\n");
        DEBUG_LOG("submit success");
    } else {
        fprintf(stderr, "submit failed:%s\n", response);
        ERROR_LOG("submit failed:%s", response);
    }

release:
    curl_easy_cleanup(curl);

end:
    free(item->md5);
    free(arg);
}

/* At present, there some bugs in this function.
static void submit_file_info(void *arg) {
    task_item *item = (task_item *)arg;
    ghttp_request *request = NULL;
    ghttp_status status;
    char    *buf;
    int     len;
    char    body[HTTP_BODY_SIZE];

    request = ghttp_request_new();
    if (!request) {
        fprintf(stderr, "ghttp_request_new failed\n");
        ERROR_LOG("ghttp_request_new failed");
        _exit(1);
    }
    ghttp_set_type(request, ghttp_type_post);
    ghttp_set_uri(request, g_reportaddr);
    ghttp_set_header(request, http_hdr_Content_Type, 
            "application/x-www-form-urlencoded");
    if (g_host) {
        ghttp_set_header(request, http_hdr_Host, g_host);
    }

    snprintf(body, HTTP_BODY_SIZE, "action=%c&host=%s&md5s=%s",
            item->action, g_hostname, item->md5);
    ghttp_set_body(request, body, strlen(body));
    ghttp_prepare(request);
    status = ghttp_process(request);
    if (status == ghttp_error) {
        fprintf(stderr, "ghttp_process failed\n");
        ERROR_LOG("ghttp_process failed");
    } else if (status == ghttp_done) {
        buf = ghttp_get_body(request);
        len = ghttp_get_body_len(request);
        if (strcmp(buf, "success") == 0) {
            printf("submit success\n");
            DEBUG_LOG("submit success");
        } else {
            fprintf(stderr, "submit failed:%s\n", buf);
            ERROR_LOG("submit failed:%s", buf);
        }
    }

    free(arg);
}
*/

static void submit_file(char action, char *md5) {
    task_item *item;

    /* The allocated memory freed in submit_file_info(). */
    item = (task_item*)malloc(sizeof(*item));
    if (!item) {
        fprintf(stderr, "Out of memory\n");
        ERROR_LOG("Out of memory");
        return;
    }

    item->action = action;
    item->md5 = strdup(md5);
    if (!item->md5) {
        free(item);
        fprintf(stderr, "Out of memory\n");
        ERROR_LOG("Out of memory");
        return;
    }

    if (threadpool_add_task(g_pool, submit_file_info, item, 0) != 0) {
        fprintf(stderr, "Add task to threadpool failed:%s\n", md5);
        ERROR_LOG("Add task to threadpool failed:%s", md5);
        free(item->md5);
        free(item);
    }
}


static int ext_is_valid(char *extension) {
    int i = 0;

    for (i = 0; exten[i]; ++i) {
        if (!strcasecmp(extension, exten[i])) {
            return 1;
        }
    }

    return 0;
}

static int dir_ev_handler(struct inotify_event *event) {
    char full_path[MAX_PATH_LEN];
    static char moved_from[MAX_PATH_LEN] = {};

    inotifytools_snprintf(full_path, MAX_PATH_LEN, event, "%w%f");

    if (event->mask & IN_CREATE) {
        /* Monitor the new directory created or moved to here. */
        if (!inotifytools_watch_recursively(full_path, MONI_EVENTS)) {
            ERROR_LOG("Add watch to directory '%s' failed", full_path);
            fprintf(stderr, "Add watch to directory '%s' failed\n", full_path);
            return -1;
        }
        DEBUG_LOG("Add watch to directory '%s'", full_path);
        printf("Add watch to directory '%s'\n", full_path);
    } else if (event->mask & IN_MOVED_TO) {
        if (moved_from[0] != '\0') {
            inotifytools_replace_filename(moved_from, full_path);
            memset(moved_from, 0, sizeof(moved_from));
            DEBUG_LOG("Move directory from '%s' to '%s'", 
                moved_from, full_path);
            printf("Move directory from '%s' to '%s'\n", 
                moved_from, full_path);
        } else {
            if (!inotifytools_watch_recursively(full_path, MONI_EVENTS)) {
                ERROR_LOG("Add watch to directory '%s' failed", full_path);
                fprintf(stderr, "Add watch to directory '%s' failed\n", 
                        full_path);
                return -1;
            }
            DEBUG_LOG("Directory '%s' was moved here", full_path);
            printf("Directory '%s' was moved here\n", full_path);
        }
    } else if (event->mask & IN_DELETE) {
        if (!inotifytools_remove_watch_by_filename(full_path)) {
            ERROR_LOG("Remove watch from directory '%s' failed", full_path);
            fprintf(stderr, "Remove watch from directory '%s' failed\n", 
                    full_path);
            return -1;
        }
        DEBUG_LOG("Directory '%s' was removed", full_path);
        printf("Directory '%s' was removed\n", full_path);
    } else if (event->mask & IN_MOVED_FROM) {
        strcpy(moved_from, full_path);
        if (!inotifytools_remove_watch_by_filename(full_path)) {
            memset(moved_from, 0, sizeof(moved_from));
            ERROR_LOG("Remove watch from directory '%s' failed", full_path);
            fprintf(stderr, "Remove watch from directory '%s' failed\n", 
                    full_path);
            return -1;
        }
    }

    return 0;
}

static int file_ev_handler(struct inotify_event *event) {
    char full_path[MAX_PATH_LEN];
    int len, i;
    /* Must be `unsigned char'. */
    unsigned char hash[16];
    char key[KEY_LEN];
    char *ptr = key;
    char *end = ptr + KEY_LEN;
    char *filepath;
    char *extension;
    struct stat st;

    inotifytools_snprintf(full_path, MAX_PATH_LEN, event, "%w%f");
    len = strlen(full_path);
    if (full_path[len - 1] == '/') {
        /* Filter the directory names. */
        return 0;
    }

    if ((extension = strrchr(full_path, '.')) == NULL) {
        return 0;
    }
    ++extension;
    if (!ext_is_valid(extension)) {
        return 0; /* skip invalid extensions */
    }

    filepath = full_path + strlen(global_conf.moni_dir);
    if (*filepath == '/') {
        ++filepath;
    }

    if (event->mask & IN_DELETE || event->mask & IN_MOVED_FROM) {
        md5(hash, (unsigned char*)filepath, strlen(filepath));
        ptr = key;
        for (i = 0; i < 16; ++i) {
            ptr += snprintf(ptr, end - ptr, "%02x", hash[i]);
        }   
        snprintf(ptr, end - ptr, "|%lu", (long)0);

        submit_file(ACTION_DEL, key);
        DEBUG_LOG("%s deleted", filepath);
        printf("%s deleted\n", filepath);
    } else if (event->mask & IN_CREATE) {
        /* do nothing, just log */
        DEBUG_LOG("%s created", filepath);
        printf("%s created\n", filepath);
    } else if (event->mask & (
                IN_CLOSE_WRITE  |
                IN_MOVED_TO     | 
                IN_ATTRIB
                )) {
        if (stat(full_path, &st) != 0) {
            ERROR_LOG("stat %s failed: %s", full_path, strerror(errno));
            fprintf(stderr, "stat %s failed: %s\n", full_path, 
                    strerror(errno));
            return -1;
        }

        md5(hash, (unsigned char*)filepath, strlen(filepath));
        ptr = key;
        for (i = 0; i < 16; ++i) {
            ptr += snprintf(ptr, end - ptr, "%02x", hash[i]);
        }   
        snprintf(ptr, end - ptr, "|%lu", st.st_size);

        submit_file(ACTION_ADD_OR_MOD, key);
        DEBUG_LOG("%s modified or created", filepath);
        printf("%s modified or created\n", filepath);
    } else {
        WARNING_LOG("%s failed", filepath);
        fprintf(stderr, "%s failed\n", filepath);
        /* Never get here */
        return -1;
    }
    return 0;
}

int moni(char *monidir) {
    struct inotify_event *event;

    if (exclude[0]) {
        if (!inotifytools_initialize() 
                || !inotifytools_watch_recursively_with_exclude(monidir, 
                    MONI_EVENTS, (char const **)exclude)) {
            ERROR_LOG("%s:%s", strerror(inotifytools_error()), monidir);
            fprintf(stderr, "%s:%s\n", strerror(inotifytools_error()), monidir);
            return -1;
        }
    } else {
        if (!inotifytools_initialize() 
                || !inotifytools_watch_recursively(monidir, 
                    MONI_EVENTS)) {
            ERROR_LOG("%s:%s", strerror(inotifytools_error()), monidir);
            fprintf(stderr, "%s:%s\n", strerror(inotifytools_error()), monidir);
            return -1;
        }
    }

    inotifytools_set_printf_timefmt("%F %T");

    /* Now wait till we get a event. */
    do {
        event = inotifytools_next_event(-1);
        if (!event) {
            ERROR_LOG("%s", strerror(inotifytools_error()));
            fprintf(stderr, "%s\n", strerror(inotifytools_error()));
            continue;
        }

        if (event->mask & IN_ISDIR) {
            if (dir_ev_handler(event) < 0) {
                continue;
            }
        } else {
            if (file_ev_handler(event) < 0) {
                continue;
            }
        }
    } while (1);

    /* Never get here. */
    return -1;
}

static int init_hostname() {
    int ret;
    g_hostname_size = HOSTNAME_LEN;
    g_hostname = (char *)malloc(g_hostname_size);
    assert(g_hostname);
    for ( ; ; ) {
        if ((ret = gethostname(g_hostname, g_hostname_size)) != 0) {
            if (errno == EINVAL) {
                g_hostname_size += HOSTNAME_LEN;
                g_hostname = (char *)realloc(g_hostname, g_hostname_size);
                assert(g_hostname);
                continue;
            }
        }
        break;
    }

    return ret;
}

static int ftw_cb(const char *fpath, const struct stat *st,
        int tflag, struct FTW *ftwbuf) {
    int i = 0;
    struct timespec ts;
    char key[KEY_SIZE];
    char *ptr = key;
    char *end = ptr + KEY_SIZE;
    char *filepath;
    char *extension = NULL;
    unsigned char hash[16];

    if (tflag == FTW_D) {
        for (i = 0; exclude[i]; ++i) {
            if (!strcmp(exclude[i], fpath)) {
                return FTW_SKIP_SUBTREE;
            }
        }
        return FTW_CONTINUE; /* skip directory. */
    }

    if (tflag == FTW_SL) {
        struct stat st;
        if (stat(fpath, &st) < 0) {
            fprintf(stderr, "stat %s failed:%s\n", fpath, strerror(errno));
        } else if (S_ISREG(st.st_mode)) {
            goto conti;
        } else if (S_ISDIR(st.st_mode)) {
            nftw(fpath, ftw_cb, 20, FTW_ACTIONRETVAL);
        }
        return FTW_CONTINUE;
    }

conti:
    if (global_conf.valid_exten) {
        if ((extension = strrchr(fpath, '.')) == NULL) {
            printf("No extension:%s\n", fpath);
            return 0;
        }
        ++extension;
        if (!ext_is_valid(extension)) {
            return 0; /* skip invalid extensions */
        }
    }
    
    if (!(filepath = strstr(fpath, global_conf.moni_dir))) {
        ERROR_LOG("Invalid file path:fpath=%s, moni_dir=%s", 
                fpath, global_conf.moni_dir);
        fprintf(stderr, "Invalid file path:fpath=%s, moni_dir=%s\n", 
                fpath, global_conf.moni_dir);
        return 0;
    }

    filepath += strlen(global_conf.moni_dir);
    if (*filepath == '/') {
        ++filepath;
    }

    md5(hash, (unsigned char*)filepath, strlen(filepath));
    for (i = 0; i < 16; ++i) {
        ptr += snprintf(ptr, end - ptr, "%02x", hash[i]);
    }

    DEBUG_LOG("File: %s, MD5: %s, SIZE: %lu", filepath, key, st->st_size);
    if (*md5_buf == '\0') {
        snprintf(md5_buf, MD5_BUF_SIZE, "%s|%lu", key, st->st_size);
    } else {
        snprintf(md5_buf + strlen(md5_buf), MD5_BUF_SIZE - strlen(md5_buf),
            "#%s|%lu", key, st->st_size);
        if (MD5_BUF_SIZE - strlen(md5_buf) < KEY_LEN) {
            submit_file(ACTION_ADD_OR_MOD, md5_buf);
            *md5_buf = '\0';
        }
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 100;
    nanosleep(&ts, NULL);
    return 0; /* continue */
}

static struct option long_options[] = {
    {"moni-dir", required_argument, NULL, 'd'},
    {"exclude", required_argument, NULL, 'e'},
    {"valid-exten", required_argument, NULL, 'a'},
    {"report-addr", required_argument, NULL, 'r'},
    {"report-host", required_argument, NULL, 'h'},
    {"thread-init", required_argument, NULL, 't'},
    {"thread-max", required_argument, NULL, 'x'},
    {"thread-stack", required_argument, NULL, 's'},
    {"log-dir", required_argument, NULL, 'i'},
    {"log-name", required_argument, NULL, 'f'},
    {"log-level", required_argument, NULL, 'l'},
    {"log-size", required_argument, NULL, 'z'},
    {"log-num", required_argument, NULL, 'n'},
    {"log-multi", required_argument, NULL, 'm'},
    {"config", required_argument, NULL, 'c'},
    {"verbose", no_argument, NULL, 'v'},
    {"version", 0, NULL, 'V'},
    {"help", 0, NULL, 'H'},
};

static void filmon_usage() {
    printf("usage: filmon [--config=conf_file|--help|--version|OPTIONS]"
            " [--verbose]\n");
    printf("\nOPTIONS:\n");
    printf("  --moni-dir|-d       directory to monitor\n");
    printf("  --exclude|-e        exclude directory\n");
    printf("  --valid-exten|-a    valid externsion\n"); 
    printf("  --report-addr|-r    file list server address\n");
    printf("  --report-host|-h    file list server host\n");
    printf("  --thread-init|-t    initialized number of threads"
            " in thread pool\n");
    printf("  --thread-max|-x     max number of threads in thread pool\n");  
    printf("  --thread-stack|-s   stack size of a thread\n");
    printf("  --log-dir|-i        log directory\n");
    printf("  --log-name|-f       log file name\n");
    printf("  --log-level|-l      log level\n");
    printf("  --log-size|-z       log file size\n");
    printf("  --log-num|-n        count of log file\n");
    printf("  --log-multi|-m      multi or single file name\n");
    printf("  --config|-c         use config file instead of OPTIONS\n");
    printf("  --verbose|-v        verbose mode\n");
    printf("  --version|-V        print version information\n");
    printf("  --help|-H           print help information\n");
}

#ifdef DEBUG
void rlimit_reset() {
    struct rlimit rlim;

    /* Alow core dump */
    rlim.rlim_cur = 1 << 29;
    rlim.rlim_max = 1 << 29;
    setrlimit(RLIMIT_CORE, &rlim);
}
#endif /* DEBUG */

void sig_handler(int signo) {
    FATAL_LOG("Receive signo:%d", signo);
    exit(111);
}

static void set_sig_handlers() {
    int r;
    struct sigaction sa; 

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    r = sigemptyset(&sa.sa_mask);

    if (r == -1) {
        fprintf(stderr, "sigemptyset() failed:%s\n", strerror(errno));
        exit(111);
    }

    sigaction(SIGPIPE, &sa, 0); 
    sa.sa_handler = sig_handler;

    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGINT, &sa, 0);
    sigaction(SIGQUIT, &sa, 0);
}

int main(int argc, char **argv) {
    int flags = FTW_ACTIONRETVAL | FTW_PHYS;
    int c, ret;
    char *conf_file = NULL;
    config_t g_conf;
    int verbose = 0;
    char header_buf[128];
    
#ifdef DEBUG
    rlimit_reset();
#endif /* DEBUG */

    set_sig_handlers();

    while ((c = getopt_long(argc, argv, "d:e:a:r:h:t:x:s:i:f:l:z:n:m:c:vVH", 
                long_options, NULL)) != -1) {
        switch (c) {
        case 'm':
            global_conf.log_multi = atoi(optarg);
            break;
        case 'n':
            global_conf.log_num = atoi(optarg);
            break;
        case 'z':
            global_conf.log_size = atoi(optarg);
            break;
        case 'l':
            global_conf.log_level = atoi(optarg);
            break;
        case 'i':
            global_conf.log_dir = optarg;
            break;
        case 'f':
            global_conf.log_name = optarg;
            break;
        case 's':
            global_conf.thread_stack = atoi(optarg);
            break;
        case 'x':
            global_conf.thread_max = atoi(optarg);
            break;
        case 't':
            global_conf.thread_init = atoi(optarg);
            break;
        case 'V':
            printf("filmon: %s, compiled at %s %s\n", 
                    FILMON_VERSION, __DATE__, __TIME__);
            exit(0);
        case 'H':
            filmon_usage();
            exit(0);
        case 'v':
            verbose = 1;
            break;
        case 'c':
            conf_file = optarg;
            break;
        case 'd':
            global_conf.moni_dir = optarg;
            break;
        case 'e':
            global_conf.exclude = optarg;
            break;
        case 'a':
            global_conf.valid_exten = optarg;
            break;
        case 'r':
            global_conf.report_addr = optarg;
            break;
        case 'h':
            global_conf.report_host = optarg;
            break;
        }
    }

    if (argc != optind) {
        filmon_usage();
        exit(1);
    }

    /* Parse conf file. */
    if (conf_file) {
        ret = config_init(&g_conf, conf_file);
        if (ret != 0) {
            boot_notify(-1, "Load conf file %s", conf_file);
            exit(1);
        }

        global_conf.moni_dir = config_get_str_value(&g_conf, 
                "moni_dir", "/usr/local/apache2/htdocs");
        global_conf.exclude = config_get_str_value(&g_conf,
                "exclude", NULL);
        global_conf.valid_exten = config_get_str_value(&g_conf, 
            "valid_exten", NULL);
        global_conf.report_addr = config_get_str_value(&g_conf, 
            "report_addr", NULL);
        global_conf.report_host = config_get_str_value(&g_conf, 
            "report_host", NULL);
        global_conf.thread_init = 
            config_get_int_value(&g_conf, "thread_init", 10);
        global_conf.thread_max =
            config_get_int_value(&g_conf, "thread_max", 20);
        global_conf.thread_stack =
            config_get_int_value(&g_conf, "thread_stack", 1048576);
        global_conf.log_dir = config_get_str_value(&g_conf, "log_dir", ".");
        global_conf.log_name = config_get_str_value(&g_conf, "log_name", 
            "filmond.log");
        global_conf.log_level = config_get_int_value(&g_conf, 
            "log_level", LOG_LEVEL_ALL);
        global_conf.log_size = config_get_int_value(&g_conf, 
            "log_size", LOG_FILE_SIZE);
        global_conf.log_num = config_get_int_value(&g_conf, 
            "log_num", LOG_FILE_NUM),
        global_conf.log_multi = config_get_int_value(&g_conf, 
            "log_multi", LOG_MULTI_NO);
    } else {
        if (!global_conf.moni_dir) 
            global_conf.moni_dir = "/usr/local/apache2/htdocs";
        if (!global_conf.thread_init) 
            global_conf.thread_init = 10;
        if (!global_conf.thread_max)
            global_conf.thread_max = 20;
        if (!global_conf.thread_stack) 
            global_conf.thread_stack = 1048576;
        if (!global_conf.log_dir) 
            global_conf.log_dir = ".";
        if (!global_conf.log_name) 
            global_conf.log_name = "filmond.log";
        if (!global_conf.log_level)
            global_conf.log_level = LOG_LEVEL_ALL;
        if (!global_conf.log_size)
            global_conf.log_size = LOG_FILE_SIZE;
        if (!global_conf.log_num)
            global_conf.log_num = LOG_FILE_NUM;
        if (!global_conf.log_multi)
            global_conf.log_multi = LOG_MULTI_NO;
    }

    if (global_conf.valid_exten) {
        str_explode(NULL, (unsigned char *)global_conf.valid_exten, 
                (unsigned char **)exten, 30);
    }

    if (global_conf.exclude) {
        str_explode(NULL, (unsigned char *)global_conf.exclude,
                (unsigned char **)exclude, 29);
    }
    
    /* Initialize log file */
    ret = log_init(global_conf.log_dir, 
            global_conf.log_name,
            global_conf.log_level,
            global_conf.log_size,
            global_conf.log_num,
            global_conf.log_multi);
    if (ret != 0) {
        boot_notify(-1, "Initialize log file");
        exit(1);
    }

    if (!global_conf.report_addr) {
        boot_notify(-1, "No report address");
        exit(1);
    }

    if (global_conf.report_host) {
        snprintf(header_buf, 128, "Host: %s", global_conf.report_host);
        list = curl_slist_append(list, header_buf);
    }

    if (init_hostname() != 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        boot_notify(-1, "Get hostname");
    }

    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        fprintf(stderr, "curl_global_init failed:\n");
        boot_notify(-1, "Initialize curl");
        exit(1);
    }

    if (!verbose) {
        int fd;
        if ((fd = open("/dev/null", O_WRONLY)) < 0) {
            boot_notify(-1, "Open /dev/null");
            exit(1);
        }

        if (dup2(fd, STDOUT_FILENO) < 0) {
            boot_notify(-1, "Dup STDOUT to /dev/null");
            exit(1);
        }
    }

    /* Create threadpool. */
    g_pool = threadpool_create(
            global_conf.thread_init,
            global_conf.thread_max,
            global_conf.thread_stack);
    assert(g_pool);

    /* Submit all files to server. */
    if (nftw(global_conf.moni_dir, ftw_cb, 20, flags) != 0) {
        fprintf(stderr, "nftw failed:%s\n", strerror(errno));
        ERROR_LOG("nftw failed:%s", strerror(errno));
    }

    if (*md5_buf != '\0') {
        submit_file(ACTION_ADD_OR_MOD, md5_buf);
        *md5_buf = '\0';
    }

    if (moni(global_conf.moni_dir) != 0) {
        FATAL_LOG("filmon exit abnormally");
        fprintf(stderr, "filmon exit abnormally\n");
    }

    curl_slist_free_all(list);
    curl_global_cleanup();
    FATAL_LOG("Should never get here!");
    exit(1);
}
