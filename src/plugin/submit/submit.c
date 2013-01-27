#include <string.h>
#include <pwd.h>
#include <errno.h>
#include "plugin.h"
#include "md5.h"
#include "log.h"
#include "base64.h"
#include "version.h"
#include "threadpool.h"
#include "curl/curl.h"
#include "json/json.h"

#define KEY_SIZE            33
#define URI_LIMIT           1024
#define RESPONSE_LIMIT      1024
#define BUF_SIZE            1024
#define MIN(a, b)           ((a) < (b) ? (a) : (b))

#define ACTION_ADD_OR_MOD   'a'
#define ACTION_DEL          'd'


typedef struct thread_ctx_s {
    json_object           *files_json;
    threadpool_t          *pool;
    int                    count;
} thread_ctx_t;


static struct curl_slist  *list;
static char               *submit_addr;
static char               *submit_host;
static char               *moni_dir;
static thread_ctx_t       *thread_ctxs;
static int                 thread_num;
static char                add_uri[URI_LIMIT];
static char                delete_uri[URI_LIMIT];
static int                 thread_stack;


typedef struct task_item_s {
    int             action;
    char           *post;
} task_item_t;


static int get_pool_id(const char *filepath) {
    unsigned int h = 5381;
    const char *ptr = filepath;

    while (*ptr != '\0') {
        h = (h + (h << 5)) + (*ptr++);
    }

    return h % thread_num;
}


static void add_fileinfo_json(json_object *obj, char *filepath, 
        const struct stat *st) {
    char             buf[BUF_SIZE] = {};
    char            *buf_big = NULL;
    int              filepath_len;
    int              base64_len;
    int              i;
    struct passwd    pw, *ret_pw;
    json_object     *fileinfo_json;
    unsigned char    hash[16];
    char             key[KEY_SIZE];
    char            *ptr = key;
    char            *end = ptr + KEY_SIZE;

    /*
     * calculate MD5 of 'filepath'
     */
    md5(hash, (unsigned char*)filepath, strlen(filepath));
    for (i = 0; i < 16; ++i) {
        ptr += snprintf(ptr, end - ptr, "%02x", hash[i]);
    }

    if (st == NULL) { /* for DELETE event */
        json_object_object_add(obj, key, json_object_new_object());
        return;
    }

    ptr = buf;

    /*
     * calculate BASE64 of 'filepath'
     */
    filepath_len = strlen(filepath);
    if ((filepath_len + 2) / 3 * 4 >= BUF_SIZE) {
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

    json_object_object_add(obj, key, fileinfo_json);

    DEBUG_LOG("File: %s, MD5: %s, SIZE: %lu", filepath, key, st->st_size);

    if (buf_big) {
        free(buf_big);
    }
}


static size_t curl_write_cb(char *ptr, size_t size, 
        size_t count, void *buf) {
    size_t n = MIN((size * count), RESPONSE_LIMIT - strlen((char *)buf));
    memcpy((char *)buf + strlen((char *)buf), ptr, n);
    return n;
}


/* Task callback called by thread in threadpool. */
static void submit_file_info(void *arg) {
    CURL         *curl;
    json_object  *obj;
    task_item_t  *item = (task_item_t *)arg;
    char          response[RESPONSE_LIMIT] = {}; /* Must clear data with '0' */
    CURLcode      res;
    long          rc = 0;

    curl = curl_easy_init();
    if (!curl) {
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

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, item->post);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    res = curl_easy_perform(curl);
    if (res != 0) {
        ERROR_LOG("curl_easy_perform failed:%s", curl_easy_strerror(res));
        goto release;
    }

    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &rc);
    if (res != 0) {
        ERROR_LOG("curl_easy_getinfo failed:%s", curl_easy_strerror(res));
        goto release;
    }

    if (rc != 200) {
        ERROR_LOG("submit failed: HTTP CODE: %ld", rc);
        goto release;
    }

    response[RESPONSE_LIMIT - 1] = '\0';

    obj = json_tokener_parse(response);
    if (is_error(obj) || json_object_get_type(obj) != json_type_object) {
        ERROR_LOG("Invalid json string: %s", response);
    } else {
        struct json_object *j = json_object_object_get(obj, "error");
        if (!j) {
            ERROR_LOG("Invalid json string: %s", response);
        } else {
            if (json_object_get_type(j) != json_type_string) {
                ERROR_LOG("Invalid json string: %s", response);
            } else {
                if (strcmp("no error", json_object_get_string(j))) {
                    ERROR_LOG("Invalid json string: %s", response);
                } else {
                    DEBUG_LOG("submit success");
                }
            }
        }
    }

    json_object_put(obj);

release:
    curl_easy_cleanup(curl);

end:
    free(item->post);
    free(arg);
}


static void submit_file(char action, json_object *obj, int pool_id) {
    task_item_t     *item;

    /* The allocated memory freed in submit_file_info(). */
    item = (task_item_t *)malloc(sizeof(*item));
    if (!item) {
        ERROR_LOG("Out of memory");
        return;
    }

    item->action = action;
    item->post = strdup(json_object_get_string(obj));

    if (!item->post) {
        free(item);
        ERROR_LOG("Out of memory");
        return;
    }

    if (threadpool_add_task(thread_ctxs[pool_id].pool, 
                            submit_file_info, item, 0) != 0) {
        ERROR_LOG("Add task to threadpool failed: %s", item->post);
        free(item->post);
        free(item);
    }
}


int plugin_file_ftw(const char *filepath, const struct stat *st) {
    int pool_id = get_pool_id(filepath);

    if (thread_ctxs[pool_id].files_json == NULL) {
        thread_ctxs[pool_id].files_json = json_object_new_object();
    }

    add_fileinfo_json(thread_ctxs[pool_id].files_json, (char *)filepath, st);

    if (++thread_ctxs[pool_id].count >= 30) {
        submit_file(ACTION_ADD_OR_MOD, thread_ctxs[pool_id].files_json,
                    pool_id);
        json_object_put(thread_ctxs[pool_id].files_json);
        thread_ctxs[pool_id].files_json = NULL;
        thread_ctxs[pool_id].count = 0;
    }

    return FILMOND_DECLINED;
}


/*
 * moved_from is valid only when action is ACTION_FILE_MOVE
 */
int plugin_file_event(int action, char *filepath, char *moved_from) {
    struct stat      st;
    json_object     *files_obj;
    char            *path;
    int              pool_id;
    

    switch (action) {
    case ACTION_FILE_ATTRIB:
    case ACTION_FILE_MODIFY:
        path = filepath + strlen(moni_dir);
        if (*path == '/') {
            ++path;
        }

        pool_id = get_pool_id(path);

        if (stat(filepath, &st) < 0) {
            ERROR_LOG("stat %s failed:%s", filepath, strerror(errno));
            return FILMOND_DECLINED;
        }

        files_obj = json_object_new_object();
        add_fileinfo_json(files_obj, path, &st);
        submit_file(ACTION_ADD_OR_MOD, files_obj, pool_id);
        json_object_put(files_obj);
        break;

    case ACTION_FILE_MOVE:
        path = moved_from + strlen(moni_dir);
        if (*path == '/') {
            ++path;
        }

        pool_id = get_pool_id(path);

        files_obj = json_object_new_object();
        add_fileinfo_json(files_obj, path, NULL);
        submit_file(ACTION_DEL, files_obj, pool_id);
        json_object_put(files_obj);
        break;

    case ACTION_FILE_DELETE:
        path = filepath + strlen(moni_dir);
        if (*path == '/') {
            ++path;
        }

        pool_id = get_pool_id(path);

        files_obj = json_object_new_object();
        add_fileinfo_json(files_obj, path, NULL);
        submit_file(ACTION_DEL, files_obj, pool_id);
        json_object_put(files_obj);
        break;
    }

    return FILMOND_DECLINED;
}


int plugin_init(conf_t *conf) {
    int   i;
    char  header_buf[128];

    moni_dir = conf_get_str_value(conf, "moni_dir",
        "/usr/local/apache2/htdocs");
    submit_addr = conf_get_str_value(conf, "submit_addr", NULL);
    submit_host = conf_get_str_value(conf, "submit_host", NULL);
    thread_stack = conf_get_int_value(conf, "thread_stack", 1048576);
    thread_num = conf_get_int_value(conf, "thread_num", 10);

    if (!submit_addr) {
        boot_notify(-1, "No submit address");
        return FILMOND_ERROR;
    }

    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        boot_notify(-1, "Initialize curl");
        return FILMOND_ERROR;
    }

    /*
     * set by calloc():
     *
     *      thread_ctxs[i].json_files = NULL;
     *      thread_ctxs[i].count = 0;
     *
     */
    thread_ctxs = (thread_ctx_t *)calloc(sizeof(thread_ctx_t), thread_num);
    if (thread_ctxs == NULL) {
        boot_notify(-1, "Out of memory");
        return FILMOND_ERROR;
    }

    snprintf(add_uri, URI_LIMIT, "%s?host=%s&action=add", submit_addr, 
        g_hostname);

    snprintf(delete_uri, URI_LIMIT, "%s?host=%s&action=delete", submit_addr,
        g_hostname);

    for (i = 0; i < thread_num; ++i) {
        thread_ctxs[i].pool = threadpool_create(1, 1, thread_stack);
        assert(thread_ctxs[i].pool);
    }

    if (submit_host) {
        snprintf(header_buf, 128, "Host: %s", submit_host);
        list = curl_slist_append(list, header_buf);
    }

    list = curl_slist_append(list, "Content-Type: application/json");

    return FILMOND_DECLINED;
}


int plugin_deinit(conf_t *conf) {
    int  i;

    curl_slist_free_all(list);

    curl_global_cleanup();

    for (i = 0; i < thread_num; ++i) {
        threadpool_destroy(thread_ctxs[i].pool, 1, 10);
    }

    free(thread_ctxs);

    return FILMOND_DECLINED;
}

int plugin_ftw_post() {
    int  i;

    for (i = 0; i < thread_num; ++i) {
        if (thread_ctxs[i].count > 0) {
            submit_file(ACTION_ADD_OR_MOD, thread_ctxs[i].files_json, i);
            json_object_put(thread_ctxs[i].files_json);
            thread_ctxs[i].files_json = NULL;
            thread_ctxs[i].count = 0;
        }
    }

    return FILMOND_DECLINED;
}


void __submit_plugin_main(void) {
    printf("*** filmond [submit] plugin ***\n");
    printf("'submit' plugin used to submit file "
           "information to remote server.\n");
    printf("filmond version: %s\n", FILMOND_VERSION);
    printf("%s\n", FILMOND_COPYRIGHT);
    exit(0);
}
