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
#include <pwd.h>
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
#include "base64.h"
#include "version.h"
#include "json/json.h"


#define KEY_SIZE            33
#define MAX_PATH_LEN        4096
#define HOSTNAME_LEN        128
#define URI_LIMIT           1024
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
json_object *files_json;
char add_uri[URI_LIMIT];
char delete_uri[URI_LIMIT];


struct global_conf_st {
    char    *moni_dir;
    char    *exclude;
    char    *valid_exten;
    char    *report_addr;
    char    *report_host;
    int     thread_stack;
    char    *log_dir;
    char    *log_name;
    int     log_level;
    int     log_size;
    int     log_num;
    int     log_multi;
} global_conf;


typedef struct task_item {
    int             action;
    char           *post;
} task_item;


static void filmond_ftw(void *arg);


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
    long rc = 0;
    json_object *obj;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init failed\n");
        ERROR_LOG("curl_easy_init failed");
        goto end;
    }

    if (item->action == ACTION_ADD_OR_MOD) {
        curl_easy_setopt(curl, CURLOPT_URL, add_uri);
    } else if (item->action == ACTION_DEL) {
        curl_easy_setopt(curl, CURLOPT_URL, delete_uri);
    } else {
        /*
         * invalid action
         */
        assert(0);
    }

    DEBUG_LOG("POST: %s", item->post);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, item->post);
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

    obj = json_tokener_parse(response);
    if (is_error(obj) || json_object_get_type(obj) != json_type_object) {
        printf("submit failed");
        ERROR_LOG("Invalid json string: %s", response);
    } else {
        struct json_object *j = json_object_object_get(obj, "error");
        if (json_object_get_type(j) != json_type_string) {
            printf("submit failed");
            ERROR_LOG("Invalid json string: %s", response);
        } else {
            if (strcmp("no error", json_object_get_string(j))) {
                printf("submit failed");
                ERROR_LOG("Invalid json string: %s", response);
            } else {
                printf("submit success\n");
                DEBUG_LOG("submit success");
            }
        }
        json_object_put(j);
    }

    json_object_put(obj);


release:
    curl_easy_cleanup(curl);

end:
    free(item->post);
    free(arg);
}


static void submit_ftw() {
    if (threadpool_add_task(g_pool, filmond_ftw, NULL, 0) != 0) {
        fprintf(stderr, "Add ftw task to threadpool failed\n");
        ERROR_LOG("Add ftw task to threadpool failed");
        exit(1);
    }
}


static void submit_file(char action, json_object *obj) {
    task_item *item;

    /* The allocated memory freed in submit_file_info(). */
    item = (task_item*)malloc(sizeof(*item));
    if (!item) {
        fprintf(stderr, "Out of memory\n");
        ERROR_LOG("Out of memory");
        return;
    }

    item->action = action;
    item->post = strdup(json_object_get_string(obj));

    if (!item->post) {
        free(item);
        fprintf(stderr, "Out of memory\n");
        ERROR_LOG("Out of memory");
        return;
    }

    if (threadpool_add_task(g_pool, submit_file_info, item, 0) != 0) {
        fprintf(stderr, "Add task to threadpool failed: %s\n", item->post);
        ERROR_LOG("Add task to threadpool failed: %s", item->post);
        free(item->post);
        free(item);
    }
}


static int ext_is_valid(char *extension) {
    int i = 0;

    if (exten[0] == NULL) {
        return 1;
    }

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


static void add_fileinfo_json(char *filepath, char *key, 
        const struct stat *st) {
    char buf[1024] = {};
    char *buf_big = NULL;
    char *ptr = buf;
    int filepath_len;
    int base64_len;
    struct passwd  pw, *ret_pw;

    json_object *fileinfo_json;

    filepath_len = strlen(filepath);
    if ((filepath_len + 2) / 3 * 4 >= 1024) {
        buf_big = malloc((filepath_len + 2) / 3 * 4);
        assert(buf_big);
        ptr = buf_big;
    }

    base64_len = base64_encode((unsigned char *)filepath, strlen(filepath),
        (unsigned char *)ptr);

    fileinfo_json = json_object_new_object();

    json_object_object_add(fileinfo_json, "filename",
        json_object_new_string_len(ptr, base64_len));

    json_object_object_add(fileinfo_json, "size", 
        json_object_new_int(st->st_size));

    json_object_object_add(fileinfo_json, "mtime",
        json_object_new_int(st->st_mtime));

    json_object_object_add(fileinfo_json, "mode",
        json_object_new_int(st->st_mode));

    assert(getpwuid_r(st->st_uid, &pw, buf, 1024, &ret_pw) == 0);

    json_object_object_add(fileinfo_json, "owner",
        json_object_new_string(pw.pw_name));

    json_object_object_add(files_json, key, fileinfo_json);

    if (buf_big) {
        free(buf_big);
    }
}

static void submit_event_post(int action, char *filepath, char *key, 
        struct stat *st) {
    assert(files_json);
    files_json = json_object_new_object();

    if (action == ACTION_DEL) {
        json_object_object_add(files_json, key, json_object_new_object());
        submit_file(ACTION_DEL, files_json);
    } else if (action == ACTION_ADD_OR_MOD) {
        add_fileinfo_json(filepath, key, st);
        submit_file(ACTION_ADD_OR_MOD, files_json);
    }

    json_object_put(files_json);
    files_json = NULL;
}


static void submit_ftw_post(char *filepath, char *key, const struct stat *st) {
    if (files_json == NULL) {
        files_json = json_object_new_object();
    }

    add_fileinfo_json(filepath, key, st);

    if (++count >= 30) {
        submit_file(ACTION_ADD_OR_MOD, files_json);
        json_object_put(files_json);
        files_json = NULL;
        count = 0;
    }
}


static int file_ev_handler(struct inotify_event *event) {
    char full_path[MAX_PATH_LEN];
    int len, i;
    /* Must be `unsigned char'. */
    unsigned char hash[16];
    char key[KEY_SIZE];
    char *ptr = key;
    char *end = ptr + KEY_SIZE;
    char *filepath;
    char *extension;
    struct stat st;

    inotifytools_snprintf(full_path, MAX_PATH_LEN, event, "%w%f");
    len = strlen(full_path);
    if (full_path[len - 1] == '/') {
        /* Filter the directory names. */
        return 0;
    }

    if (global_conf.valid_exten) {
        if ((extension = strrchr(full_path, '.')) == NULL) {
            return 0;
        }
        ++extension;
        if (!ext_is_valid(extension)) {
            return 0; /* skip invalid extensions */
        }
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

        /* Delete event don't need stat structure */
        submit_event_post(ACTION_DEL, filepath, key, NULL);

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

        submit_event_post(ACTION_ADD_OR_MOD, filepath, key, &st);
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
                || !inotifytools_watch_recursively(monidir, MONI_EVENTS)) {
            ERROR_LOG("%s:%s", strerror(inotifytools_error()), monidir);
            fprintf(stderr, "%s:%s\n", strerror(inotifytools_error()), monidir);
            return -1;
        }
    }

    inotifytools_set_printf_timefmt("%F %T");

    submit_ftw();

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

    submit_ftw_post(filepath, key, st);

    ts.tv_sec = 0;
    ts.tv_nsec = 100;
    nanosleep(&ts, NULL);
    return 0; /* continue */
}


static void filmond_ftw(void *arg) {
    int flags = FTW_ACTIONRETVAL | FTW_PHYS;

    /* Submit all files to server. */
    if (nftw(global_conf.moni_dir, ftw_cb, 20, flags) != 0) {
        fprintf(stderr, "nftw failed:%s\n", strerror(errno));
        ERROR_LOG("nftw failed:%s", strerror(errno));
    }

    if (count > 0) {
        submit_file(ACTION_ADD_OR_MOD, files_json);
        json_object_put(files_json);
        files_json = NULL;
    }
}


static struct option long_options[] = {
    {"moni-dir", required_argument, NULL, 'd'},
    {"exclude", required_argument, NULL, 'e'},
    {"valid-exten", required_argument, NULL, 'a'},
    {"report-addr", required_argument, NULL, 'r'},
    {"report-host", required_argument, NULL, 'h'},
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


static void filmond_usage() {
    printf("usage: filmond [--config=conf_file|--help|--version|OPTIONS]"
            " [--verbose]\n");
    printf("\nOPTIONS:\n");
    printf("  --moni-dir|-d       directory to monitor\n");
    printf("  --exclude|-e        exclude directory\n");
    printf("  --valid-exten|-a    valid externsion\n"); 
    printf("  --report-addr|-r    file list server address\n");
    printf("  --report-host|-h    file list server host\n");
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

    printf("%s\n", FILMOND_COPYRIGHT);
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
    int c, ret;
    char *conf_file = NULL;
    config_t g_conf;
    int verbose = 0;
    char header_buf[128];
    
#ifdef DEBUG
    rlimit_reset();
#endif /* DEBUG */

    set_sig_handlers();

    while ((c = getopt_long(argc, argv, "d:e:a:r:h:s:i:f:l:z:n:m:c:vVH", 
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
        case 'V':
            printf("filmond: %s, compiled at %s %s\n", 
                   FILMOND_VERSION, __DATE__, __TIME__);
            printf("%s\n", FILMOND_COPYRIGHT);
            exit(0);
        case 'H':
            filmond_usage();
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
        filmond_usage();
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
        if (!global_conf.moni_dir) {
            global_conf.moni_dir = "/usr/local/apache2/htdocs";
        }

        if (!global_conf.thread_stack) {
            global_conf.thread_stack = 1048576;
        }

        if (!global_conf.log_dir) {
            global_conf.log_dir = ".";
        }

        if (!global_conf.log_name) {
            global_conf.log_name = "filmond.log";
        }

        if (!global_conf.log_level) {
            global_conf.log_level = LOG_LEVEL_ALL;
        }

        if (!global_conf.log_size) {
            global_conf.log_size = LOG_FILE_SIZE;
        }

        if (!global_conf.log_num) {
            global_conf.log_num = LOG_FILE_NUM;
        }
        
        if (!global_conf.log_multi) {
            global_conf.log_multi = LOG_MULTI_NO;
        }
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

    list = curl_slist_append(list, "Content-Type: application/json");

    if (init_hostname() != 0) {
        fprintf(stderr, "%s\n", strerror(errno));
        boot_notify(-1, "Get hostname");
        exit(1);
    }

    snprintf(add_uri, URI_LIMIT, "%s?host=%s&action=add", 
        global_conf.report_addr, g_hostname);

    snprintf(delete_uri, URI_LIMIT, "%s?host=%s&action=delete", 
        global_conf.report_addr, g_hostname);

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

    /*
     * To promise FIFO of submitting, I just create one thread in the pool.
     */ 
    g_pool = threadpool_create(1, 1, global_conf.thread_stack);
    assert(g_pool);

    if (moni(global_conf.moni_dir) != 0) {
        FATAL_LOG("filmond exit abnormally");
        fprintf(stderr, "filmond exit abnormally\n");
    }

    curl_slist_free_all(list);
    curl_global_cleanup();
    FATAL_LOG("Should never get here!");
    exit(1);
}
