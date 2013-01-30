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
#include <limits.h>
#include <signal.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/inotify.h>
#include "conf.h"
#include "so.h"
#include "log.h"
#include "vector.h"
#include "plugin.h"
#include "version.h"
#include "pcre.h"
#include "inotifytools/inotify.h"
#include "inotifytools/inotifytools.h"

#define MAX_PATH_LEN        4096
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

#define EVENT_DIR           0
#define EVENT_FILE          1 

#define FILTER_ALLOW        0
#define FILTER_DENY         1


char                   *g_hostname;
static char            *exclude[30];
static int              g_hostname_size;
static vector_t         plugin_vec;
static vector_t         filter_vec;              
static int              filter_mode;
static volatile int     stop;
static char             moved_from[MAX_PATH_LEN];
static int              event_type;
static int              timeout;


struct global_conf_st {
    char    *plugin_dir;
    char    *moni_dir;
    char    *exclude;
    char    *log_dir;
    char    *log_name;
    int      log_level;
    int      log_size;
    int      log_num;
    int      log_multi;
} global_conf;


typedef struct so_func_s {
    int (*plugin_init)(conf_t *conf);
    int (*plugin_dir_ftw)(const char *dirpath, const struct stat *st);
    int (*plugin_file_ftw)(const char *filepath, const struct stat *st);
    int (*plugin_ftw_post)();
    int (*plugin_dir_event)(int action, char *dirpath, char *moved_from);
    int (*plugin_file_event)(int action, char *filepath, char *moved_from);
    int (*plugin_deinit)(conf_t *conf);
} so_func_t;


typedef struct filmond_plugin_s {
    char        *so_name;
    void        *handle;
    so_func_t    func;
} filmond_plugin_t;


typedef struct filter_s {
    pcre        *re;
    char        *regex;
} filter_t;


static void *filmond_ftw(void *arg);


static int filter_skip(const char *path) {
    filter_t        *f;
    int              i;
    int              rc;
    
    if (filter_mode == FILTER_ALLOW) {
        for (i = 0; i < filter_vec.count; ++i) {
            f = vector_get_at(&filter_vec, i);
            rc = pcre_exec(f->re, NULL, path, strlen(path), 0, 0, NULL, 0);
            if (rc < 0) {
                switch (rc) {
                case PCRE_ERROR_NOMATCH:
                    continue;
                default:
                    ERROR_LOG("Match path \"%s\" failed: %d", path, rc);
                }
            }

            /* match succeeded */
            return 0;
        }

        return 1;

    } else {
        for (i = 0; i < filter_vec.count; ++i) {
            f = vector_get_at(&filter_vec, i);
            rc = pcre_exec(f->re, NULL, path, strlen(path), 0, 0, NULL, 0);
            if (rc < 0) {
                switch (rc) {
                case PCRE_ERROR_NOMATCH:
                    continue;
                default:
                    ERROR_LOG("Match path \"%s\" failed: %d", path, rc);
                }
            }

            /* match succeeded */
            DEBUG_LOG("Skip \"%s\" due to regex: \"%s\"", path, f->regex);
            return 1;
        }

        return 0;
    }
}


static int filter_compile(void *key, void *value, void *userptr) {
    vector_t           *vec = (vector_t *)userptr;
    const char         *err;
    int                 erroff;
    filter_t            f;

    f.re = pcre_compile((char *)value, PCRE_CASELESS, &err, &erroff, NULL);
    if (f.re == NULL) {
        boot_notify(-1, "regex compilation \"%s\" failed at offset(%d): %s",
            (char *)value, erroff, err);
        return -1;
    }
    f.regex = strdup((char *)value);
    assert(f.regex);

    vector_push(vec, &f);

    return 0;
}


static void filters_free() {
    filter_t        *f;
    int              i;
    
    for (i = 0; i < filter_vec.count; ++i) {
        f = vector_get_at(&filter_vec, i);
        pcre_free(f->re);
        if (f->regex) {
            free(f->regex);
        }
    }

    vector_destroy(&filter_vec);
}


static int filters_compile(conf_t *conf) {
    if (vector_init(&filter_vec, 4, sizeof(filter_t)) < 0) {
        return -1;
    }

    if (conf_array_foreach(conf, "path_filter", filter_compile, 
            &filter_vec) < 0) {
        return -1;
    }

    return 0;
}


static int load_filmond_plugin(void *key, void *value, void *userptr) {
    vector_t           *vec = (vector_t *)userptr;
    filmond_plugin_t    plugin;
    char                fullpath[PATH_MAX];
    symbol_t            syms[] = {
        { "plugin_init",       (void **)&plugin.func.plugin_init,       1 },
        { "plugin_dir_ftw",    (void **)&plugin.func.plugin_dir_ftw,    1 },
        { "plugin_file_ftw",   (void **)&plugin.func.plugin_file_ftw,   1 },
        { "plugin_dir_event",  (void **)&plugin.func.plugin_dir_event,  1 },
        { "plugin_file_event", (void **)&plugin.func.plugin_file_event, 1 },
        { "plugin_deinit",     (void **)&plugin.func.plugin_deinit,     1 },
        { "plugin_ftw_post",   (void **)&plugin.func.plugin_ftw_post,   1 },
        { NULL,                NULL,                                    0 }
    };

    snprintf(fullpath, PATH_MAX - 1, "%s/%s", global_conf.plugin_dir,
             (char *)value);

    plugin.so_name = strdup((char *)value);

    if (load_so(&plugin.handle, syms, fullpath) < 0) {
        return -1;
    }

    vector_push(vec, &plugin);

    return 0;
}


static int load_plugins(conf_t *conf) {
    if (vector_init(&plugin_vec, 4, sizeof(filmond_plugin_t)) < 0) {
        return -1;
    }

    if (conf_array_foreach(conf, "plugin_so", load_filmond_plugin, 
            &plugin_vec) < 0) {
        return -1;
    }

    return 0;
}


static void unload_plugins() {
    filmond_plugin_t    *plugin;
    int                  i;
    
    for (i = 0; i < plugin_vec.count; ++i) {
        plugin = vector_get_at(&plugin_vec, i);
        unload_so(&plugin->handle);
        free(plugin->so_name);
    }

    vector_destroy(&plugin_vec);
}


static int init_plugins(conf_t *conf) {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_init == NULL) {
            continue;
        }

        ret = plugin->func.plugin_init(conf);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int deinit_plugins(conf_t *conf) {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_deinit == NULL) {
            continue;
        }

        ret = plugin->func.plugin_deinit(conf);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int file_ftw_plugins(char *filepath, const struct stat *st) {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_file_ftw == NULL) {
            continue;
        }

        ret = plugin->func.plugin_file_ftw(filepath, st);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int dir_ftw_plugins(const char *dirpath, const struct stat *st) {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_dir_ftw == NULL) {
            continue;
        }

        ret = plugin->func.plugin_dir_ftw(dirpath, st);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int file_event_plugins(int action, char *filepath, char *moved_from) {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_file_event == NULL) {
            continue;
        }

        ret = plugin->func.plugin_file_event(action, filepath, moved_from);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int dir_event_plugins(int action, char *dirpath, char *moved_from) { 
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_dir_event == NULL) {
            continue;
        }

        ret = plugin->func.plugin_dir_event(action, dirpath, moved_from);

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static int ftw_post_plugins() {
    filmond_plugin_t    *plugin;
    int                  i;
    int                  ret;

    for (i = plugin_vec.count - 1; i >= 0; --i) {

        plugin = vector_get_at(&plugin_vec, i);

        if (plugin->func.plugin_ftw_post == NULL) {
            continue;
        }

        ret = plugin->func.plugin_ftw_post();

        if (ret == FILMOND_DECLINED) {
            continue;
        } else if (ret == FILMOND_DONE) {
            break;
        } else if (ret == FILMOND_ERROR) {
            return -1;
        }
    }

    return 0;
}


static void start_ftw() {
    pthread_t       tid;
    pthread_attr_t  attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    assert(pthread_create(&tid, &attr, filmond_ftw, NULL) == 0);
    pthread_attr_destroy(&attr);
}


static int timeout_handler() {

    timeout = -1;

    /*
     * If we last had MOVED_FROM and don't currently have MOVED_TO,
     * moved_from file must have been moved outside of tree, so
     * convert event to DELETE.
     */
    if (moved_from[0] != '\0') {
        if (event_type == EVENT_DIR) {
            if (!inotifytools_remove_watch_by_filename(moved_from)) {
                ERROR_LOG("Remove watch directory '%s' failed", moved_from);
                return -1;
            }
        
            if (dir_event_plugins(ACTION_DIR_DELETE, moved_from, NULL) < 0) {
                ERROR_LOG("dir_event_plugins(DELETE, \"%s\") failed", 
                    moved_from);
                return -1;
            }


        } else {
             if (file_event_plugins(ACTION_FILE_DELETE, moved_from, NULL) < 0) {
                ERROR_LOG("FILE_DELETE(\"%s\") failed", moved_from);
                return -1;
            }
        }

        moved_from[0] = '\0';
    }

    return 0;
}


static int event_handler(struct inotify_event *event) {
    char           full_path[MAX_PATH_LEN];

    timeout = -1;

    /*
     * If we last had MOVED_FROM and don't currently have MOVED_TO,
     * moved_from file must have been moved outside of tree, so
     * convert event to DELETE.
     */
    if (moved_from[0] != '\0' && !(event->mask & IN_MOVED_TO)) {

        if (event->mask & IN_ISDIR) {
            if (!inotifytools_remove_watch_by_filename(moved_from)) {
                ERROR_LOG("Remove watch directory '%s' failed", moved_from);
            }
        
            if (dir_event_plugins(ACTION_DIR_DELETE, moved_from, NULL) < 0) {
                ERROR_LOG("DIR_DELETE(\"%s\") failed", moved_from);
            }

        } else {
            if (file_event_plugins(ACTION_FILE_DELETE, moved_from, NULL) < 0) {
                ERROR_LOG("FILE_DELETE(\"%s\") failed", moved_from);
            }
        }

        moved_from[0] = '\0';
    }

    inotifytools_snprintf(full_path, MAX_PATH_LEN, event, "%w%f");

    if (!(event->mask & IN_ISDIR)) {
        int            len;
        char          *filepath;

        len = strlen(full_path);
        if (full_path[len - 1] == '/') {
            /* Filter the directory names. */
            return 0;
        }

        if (!(filepath = strstr(full_path, global_conf.moni_dir))) {
            ERROR_LOG("Invalid file path:full_path=%s, moni_dir=%s", 
                    full_path, global_conf.moni_dir);
            return 0;
        }
    
        filepath += strlen(global_conf.moni_dir);
        if (*filepath == '/') {
            ++filepath;
        }

        if (filter_skip(filepath)) {
            return 0;
        }
    }

    if (event->mask & IN_CREATE) {

        if (event->mask & IN_ISDIR) {

            if (!inotifytools_watch_recursively(full_path, MONI_EVENTS)) {
                ERROR_LOG("Add watch to directory '%s' failed", full_path);
                return -1;
            }

            DEBUG_LOG("Add watch to directory '%s'", full_path);

            if (dir_event_plugins(ACTION_DIR_CREATE, full_path, NULL) < 0) {
                ERROR_LOG("DIR_CREATE(\"%s\") failed", full_path);
                return -1;
            }
        } else {
            if (file_event_plugins(ACTION_FILE_CREATE, full_path, NULL) < 0) {
                ERROR_LOG("FILE_CREATE(\"%s\") failed", full_path);
                return -1;
            }
        }
    } else if (event->mask & IN_MOVED_TO) {
        if (moved_from[0] != '\0') {
            if (event->mask & IN_ISDIR) {
                inotifytools_replace_filename(moved_from, full_path);
    
                DEBUG_LOG("Move directory from '%s' to '%s'", 
                    moved_from, full_path);
    
                if (dir_event_plugins(ACTION_DIR_MOVE, full_path, 
                        moved_from) < 0) {
                    ERROR_LOG("DIR_MOVE(\"%s\"<-\"%s\") failed", full_path,
                        moved_from);
                    return -1;
                }
            } else {
                if (file_event_plugins(ACTION_FILE_MOVE, full_path, 
                        moved_from) < 0) {
                    ERROR_LOG("FILE_MOVE(\"%s\"<-\"%s\") failed", full_path, 
                        moved_from);
                    return -1;
                }
            }

            moved_from[0] = '\0';

        } else {
            if (event->mask & IN_ISDIR) {
                if (!inotifytools_watch_recursively(full_path, MONI_EVENTS)) {
                    ERROR_LOG("Add watch to directory '%s' failed", full_path);
                    return -1;
                }
    
                DEBUG_LOG("Directory '%s' was moved here", full_path);
    
                if (dir_event_plugins(ACTION_DIR_CREATE, full_path, NULL) < 0) {
                    ERROR_LOG("DIR_CREATE(\"%s\") failed", full_path);
                    return -1;
                }
            } else {
                if (file_event_plugins(ACTION_FILE_CREATE, full_path, 
                        NULL) < 0) {
                    ERROR_LOG("FILE_CREATE(\"%s\") failed", full_path);
                    return -1;
                }
            }
        }
    } else if (event->mask & IN_DELETE) {
        if (event->mask & IN_ISDIR) {
            if (!inotifytools_remove_watch_by_filename(full_path)) {
                ERROR_LOG("Remove watch directory '%s' failed", full_path);
                return -1;
            }
    
            DEBUG_LOG("Directory '%s' was removed", full_path);
    
            if (dir_event_plugins(ACTION_DIR_DELETE, full_path, NULL) < 0) {
                ERROR_LOG("DIR_DELETE(\"%s\") failed", full_path);
                return -1;
            }
        } else {
            if (file_event_plugins(ACTION_FILE_DELETE, full_path, NULL) < 0) {
                ERROR_LOG("FILE_DELETE(\"%s\") failed", full_path);
                return -1;
            }
        }

    } else if (event->mask & IN_MOVED_FROM) {
        strncpy(moved_from, full_path, MAX_PATH_LEN);

        if (event->mask & IN_ISDIR) {
            event_type = EVENT_DIR;
        } else {
            event_type = EVENT_FILE;
        }

        timeout = 1;
    } else if (event->mask & IN_ATTRIB) {
        if (event->mask & IN_ISDIR) {
            if (dir_event_plugins(ACTION_DIR_ATTRIB, full_path, NULL) < 0) {
                ERROR_LOG("DIR_ATTRIB(\"%s\") failed", full_path);
                return -1;
            }
        } else {
            if (file_event_plugins(ACTION_FILE_ATTRIB, full_path, NULL) < 0) {
                ERROR_LOG("FILE_ATTRIB(\"%s\") failed", full_path);
                return -1;
            }
        }

    } else if (event->mask & IN_CLOSE_WRITE) {
        if (event->mask & IN_ISDIR) {
            if (dir_event_plugins(ACTION_DIR_MODIFY, full_path, NULL) < 0) {
                ERROR_LOG("DIR_MODIFY(\"%s\") failed", full_path);
                return -1;
            }
        } else {
            if (file_event_plugins(ACTION_FILE_MODIFY, full_path, NULL) < 0) {
                ERROR_LOG("FILE_MODIFY(\"%s\") failed", full_path);
                return -1;
            }
        }
    }

    return 0;
}


static int moni(char *monidir) {
    struct inotify_event *event;

    if (exclude[0]) {
        if (!inotifytools_initialize() 
                || !inotifytools_watch_recursively_with_exclude(monidir, 
                    MONI_EVENTS, (char const **)exclude)) {
            ERROR_LOG("%s:%s", strerror(inotifytools_error()), monidir);
            return -1;
        }
    } else {
        if (!inotifytools_initialize() 
                || !inotifytools_watch_recursively(monidir, MONI_EVENTS)) {
            ERROR_LOG("%s:%s", strerror(inotifytools_error()), monidir);
            return -1;
        }
    }

    inotifytools_set_printf_timefmt("%F %T");

    start_ftw();

    /*
     * now wait till we get a event
     */ 

    timeout = -1;

    do {
        event = inotifytools_next_event(timeout);

        if (!event) {
            if (!inotifytools_error()) {
                timeout_handler();
                continue;
            }

            if (inotifytools_error() != EINTR) {
                ERROR_LOG("%s", strerror(inotifytools_error()));
                continue;
            }

            continue;
        }

        if (event->mask & IN_Q_OVERFLOW) {
            ERROR_LOG("inotify overflow:%s", strerror(inotifytools_error()));
            continue;
        }

        if (event->mask & IN_IGNORED) {
            continue;
        }

        if (event->len == 0) {
            continue;
        }

        event_handler(event);

    } while (!stop);

    return 0;
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
    int                 i = 0;
    struct timespec     ts;
    char                *filepath;

    if (stop) {
        return FTW_STOP;
    }

    if (tflag == FTW_D) {
        for (i = 0; exclude[i]; ++i) {
            if (!strcmp(exclude[i], fpath)) {
                return FTW_SKIP_SUBTREE;
            }
        }

        if (dir_ftw_plugins(fpath, st) < 0) {
            ERROR_LOG("dir_ftw_plugins failed: %s", fpath);
            return FTW_CONTINUE;
        }

        return FTW_CONTINUE; /* skip directory. */
    }

    if (tflag == FTW_SL) {
        struct stat st;
        if (stat(fpath, &st) < 0) {
            ERROR_LOG("stat %s failed:%s", fpath, strerror(errno));
        } else if (S_ISREG(st.st_mode)) {
            goto conti;
        } else if (S_ISDIR(st.st_mode)) {
            nftw(fpath, ftw_cb, 20, FTW_ACTIONRETVAL);
        }
        return FTW_CONTINUE;
    }

conti:

    if (!(filepath = strstr(fpath, global_conf.moni_dir))) {
        ERROR_LOG("Invalid file path:fpath=%s, moni_dir=%s", 
                fpath, global_conf.moni_dir);
        return 0;
    }

    filepath += strlen(global_conf.moni_dir);
    if (*filepath == '/') {
        ++filepath;
    }

    if (filter_skip(filepath)) {
        DEBUG_LOG("filepath \"%s\" skiped", filepath);
        return 0;
    }

    if (file_ftw_plugins(filepath, st) < 0) {
        ERROR_LOG("file_ftw_plugins failed: %s", filepath);
        return 0;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 100;
    nanosleep(&ts, NULL);
    return 0; /* continue */
}


static void *filmond_ftw(void *arg) {
    int flags = FTW_ACTIONRETVAL | FTW_PHYS;

    /*
     * traverse all files in monitored directory
     */
    if (nftw(global_conf.moni_dir, ftw_cb, 20, flags) != 0) {
        ERROR_LOG("nftw failed:%s", strerror(errno));
        return NULL;
    }

    if (ftw_post_plugins() < 0) {
        ERROR_LOG("ftw_post_plugins failed");
    }

    return NULL;
}


static struct option long_options[] = {
    { "config",  required_argument, NULL, 'c' },
    { "version", 0,                 NULL, 'v' },
    { "help",    0,                 NULL, 'h' },
    { NULL,      0,                 NULL, 0   },
};


static void filmond_usage() {
    printf("usage: filmond --config=conf_file|--help|--version\n\n"
           "  --config  |-c        config file instead of OPTIONS\n"
           "  --version |-v        print version information\n"
           "  --help    |-h        print help information\n");
    printf("%s\n", FILMOND_COPYRIGHT);
}


#ifdef DEBUG
static void rlimit_reset() {
    struct rlimit rlim;

    /*
     * allow core dump
     */
    rlim.rlim_cur = 1 << 29;
    rlim.rlim_max = 1 << 29;
    setrlimit(RLIMIT_CORE, &rlim);
}
#endif /* DEBUG */


static void sig_handler(int signo) {
    DEBUG_LOG("Receive signo:%d, get ready to exit", signo);

    if (stop == 1) {
        /*
         * exit rudely
         */
        _exit(1);
    }

    stop = 1;
}


static void set_sig_handlers() {
    int r;
    struct sigaction sa; 

    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    r = sigemptyset(&sa.sa_mask);

    if (r == -1) {
        boot_notify(-1, "sigemptyset failed:%s\n", strerror(errno));
        exit(1);
    }

    sigaction(SIGPIPE, &sa, 0); 
    sa.sa_handler = sig_handler;

    sigaction(SIGTERM, &sa, 0);
    sigaction(SIGINT, &sa, 0);
    sigaction(SIGQUIT, &sa, 0);
}


int main(int argc, char **argv) {
    char    *conf_file = NULL;
    int      c;
    int      ret;
    conf_t   g_conf = {};
    
#ifdef DEBUG
    rlimit_reset();
#endif /* DEBUG */

    set_sig_handlers();

    while ((c = getopt_long(argc, argv, "c:vh", long_options, NULL)) != -1) {
        switch (c) {
        case 'v':
            printf("filmond: %s, compiled at %s %s\n", 
                   FILMOND_VERSION, __DATE__, __TIME__);
            printf("%s\n", FILMOND_COPYRIGHT);
            exit(0);
        case 'h':
            filmond_usage();
            exit(0);
        case 'c':
            conf_file = optarg;
            break;
        default:
            filmond_usage();
            exit(1);
        }
    }

    if (argc != optind) {
        filmond_usage();
        exit(1);
    }

    /*
     * parse conf file.
     */
    if (conf_file) {
        char *p;

        ret = conf_init(&g_conf, conf_file);
        if (ret != 0) {
            boot_notify(-1, "Load conf file \"%s\"", conf_file);
            exit(1);
        }

        global_conf.plugin_dir = conf_get_str_value(&g_conf, 
            "plugin_dir", ".");
        global_conf.moni_dir = conf_get_str_value(&g_conf, 
            "moni_dir", "/usr/local/apache2/htdocs");
        global_conf.exclude = conf_get_str_value(&g_conf,
            "exclude", NULL);
        global_conf.log_dir = conf_get_str_value(&g_conf, "log_dir", ".");
        global_conf.log_name = conf_get_str_value(&g_conf, "log_name", 
            "filmond.log");
        global_conf.log_level = conf_get_int_value(&g_conf, 
            "log_level", LOG_LEVEL_ALL);
        global_conf.log_size = conf_get_int_value(&g_conf, 
            "log_size", LOG_FILE_SIZE);
        global_conf.log_num = conf_get_int_value(&g_conf, 
            "log_num", LOG_FILE_NUM),
        global_conf.log_multi = conf_get_int_value(&g_conf, 
            "log_multi", LOG_MULTI_NO);

        p = conf_get_str_value(&g_conf, "filter_mode", "deny");
        if (!strcasecmp(p, "allow")) {
            filter_mode = FILTER_ALLOW;
        } else if (!strcasecmp(p, "deny")) {
            filter_mode = FILTER_DENY;
        } else {
            boot_notify(-1, "Invalid filter_mode parameter");
            exit(1);
        }

        if (load_plugins(&g_conf) < 0) {
            boot_notify(-1, "Load filmond plugins");
            exit(1);
        }

        if (plugin_vec.count == 0) {
            boot_notify(-1, "NO filmond plugin loaded");
            exit(1);
        }

        if (filters_compile(&g_conf) != 0) {
            boot_notify(-1, "Compile filters");
            exit(1);
        }
    } else {
        boot_notify(-1, "NO config file specified");
        filmond_usage();
        exit(1);
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

    if (init_hostname() != 0) {
        boot_notify(-1, "Get hostname failed: %s", strerror(errno));
        exit(1);
    }

    if (init_plugins(&g_conf) < 0) {
        boot_notify(-1, "Load filmond plugins");
        exit(1);
    }

    if (moni(global_conf.moni_dir) != 0) {
        FATAL_LOG("filmond exit abnormally");
    }

    inotifytools_cleanup();

    deinit_plugins(&g_conf);

    unload_plugins();

    filters_free();

    conf_free(&g_conf);

    if (g_hostname) {
        free(g_hostname);
    }

    exit(0);
}
