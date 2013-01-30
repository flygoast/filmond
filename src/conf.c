#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <alloca.h>
#include <libgen.h>
#include <dirent.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "hash.h"
#include "conf.h"

#define CONF_TYPE_ENTRY             1
#define CONF_TYPE_BLOCK             2

#define MAX_LINE                    1024

/* "\t\n\r " */
static const unsigned char default_ifs[256] = 
    { [9]=1, [10]=1, [13]=1, [32]=1 };

int str_explode(const unsigned char *ifs, unsigned char *buf, 
        unsigned char *field[], int n) {
    int i = 0;
    unsigned char *tempifs;

    /* When ifs is NULL, use the default blanks. If the first
       byte is NULL, use the IFS table, otherwise, use the IFS
       array as a separator table. */
    if (ifs == NULL) {
        ifs = default_ifs;
    } else if (*ifs) {
        tempifs = (unsigned char *)alloca(256);
        memset((void*)tempifs, 0, 256);
        while (*ifs) {
            tempifs[*ifs++] = 1;
        }
        ifs = tempifs;
    } 

    i = 0;
    while (1) {
        /* Trim the leading separators */
        while (ifs[*buf]) {
            buf++;
        }

        if (!*buf) { 
            break;
        }

        field[i++] = buf;

        if (i >= n) { /* Process the last field. */
            buf += strlen((char *)buf) - 1;
            while (ifs[*buf]) {
                --buf;
            }
            *(buf + 1) = '\0';
            break;
        }

        while (*buf && !ifs[*buf]) {
            ++buf;
        }

        if (!*buf) {
            break;
        }
        *buf++ = '\0';
    }
    return i;
}

static int str2int(const char *strval, int def) {
    int ret = def;

    if (isdigit(strval[0]) || (strval[0] == '-' && isdigit(strval[1]))) {
        return strtol(strval, NULL, 10);
    }

    if (!strcasecmp(strval, "on")) {
        ret = 1;
    } else if (!strcasecmp(strval, "off")) {
        ret = 0;
    } else if (!strcasecmp(strval, "yes")) {
        ret = 1;
    } else if (!strcasecmp(strval, "no")) {
        ret = 0;
    } else if (!strcasecmp(strval, "true")) {
        ret = 1;
    } else if (!strcasecmp(strval, "false")) {
        ret = 0;
    } else if (!strcasecmp(strval, "enable")) {
        ret = 1;
    } else if (!strcasecmp(strval, "disable")) {
        ret = 0;
    } else if (!strcasecmp(strval, "enabled")) {
        ret = 1;
    } else if (!strcasecmp(strval, "disabled")) {
        ret = 0;
    }

    return ret;
}


static void *key_dup(const void *key) {
    return strdup((char *)key);
}

static int key_cmp(const void *key1, 
        const void *key2) {
    return strcmp((char *)key1, (char *)key2) == 0;
}

static void free_key(void *key) {
    free(key);
}

static void free_val(void *val) {
    conf_value_t *cv = (conf_value_t *)val;
    conf_entry_t *he, *next;
    if (cv->type == CONF_TYPE_ENTRY) {
        he = (conf_entry_t *)cv->value;
        while (he) {
            next = he->next;
            free(he->value);
            free(he);
            he = next;
        }
        free(cv);
    } else if (cv->type == CONF_TYPE_BLOCK) {
        conf_block_t *next_cb, *cb = (conf_block_t*)(cv->value);
        while (cb) {
            next_cb = cb->next;
            conf_free(&cb->block);
            free(cb);
            cb = next_cb;
        }
        free(cv);
    } else {
        /* never get here */
        exit (1);
    }
}

static int conf_parse_include(conf_t *conf, char *cur_file, 
        char *inc_file) {
    char dirc[PATH_MAX];
    char basec[PATH_MAX];
    char *dname;
    char *bname;
    DIR *dir = NULL;
    struct dirent *entry;
    int ret = 0, rc;
    char resolved_path[PATH_MAX];

    strncpy(dirc, (const char *)inc_file, PATH_MAX);
    strncpy(basec, (const char *)inc_file, PATH_MAX);
    dname = dirname(dirc);
    bname = basename(basec);

    if (!strcmp(bname, ".") || !strcmp(bname, "..") 
            || !strcmp(bname, "/")) {
        fprintf(stderr, "invalid include directive: %s\n", inc_file);
        return -1;
    }

    if (!(dir = opendir(dname))) {
        fprintf(stderr, "opendir %s failed:%s\n", dname, strerror(errno));
        return -1;
    }
                
    while ((entry = readdir(dir))) {
        char fullpath[PATH_MAX];
#ifdef _DIRENT_HAVE_D_TYPE
        if (entry->d_type == DT_DIR) {
            continue;
        }
#else
        struct stat st;
        if (lstat((const char *)entry->d_name, &st) != 0) {
            fprintf(stderr, "lstat %s failed: %s\n",
                    entry->d_name, strerror(errno));
            ret = -1;
            break;
        }

        if (S_ISDIR(st.st_mode)) {
            continue;
        }
#endif /* _DIRENT_HAVE_D_TYPE */
        snprintf(fullpath, PATH_MAX - 1, "%s/%s", dname, 
            entry->d_name);

        if (!realpath(fullpath, resolved_path)) {
            fprintf(stderr, "realpath %s failed:%s\n", 
                    fullpath, strerror(errno));
            ret = -1;
            break;
        }

        if (!strcmp(cur_file, resolved_path)) {
            /* skip the current file */
            continue;
        }

        if (!(rc = fnmatch(bname, entry->d_name, 
                        FNM_PATHNAME | FNM_PERIOD))) {
            if (conf_init(conf, (const char *)fullpath) != 0) {
                ret = -1;
                break;
            }
        } else if (rc == FNM_NOMATCH) {
            continue;
        } else {
            ret = -1;
            break;
        }
    }
    closedir(dir);
    return ret;
}

static char *str_sub(char *str, int start, int len) {
    int     i;
    char    *ret, *p;

    if ((len < 1) || (start < 0) || (start > strlen(str)) ||
            start + len > strlen(str)) {
        return NULL;
    }

    ret = (char *)malloc(len + 1);
    if (!ret) {
        return NULL;
    }
    p = ret;

    str += start;
    for (i = 0; i < len; ++i) {
        *p++ = *str++;
    }
    *p = '\0';
    return ret;
}

static char *conf_evaluate(conf_t *conf, char *value) {
    char    *buf = NULL;
    int     avail = MAX_LINE - 1;
    char    *scan, *p;
    int     len = 0;
    char    *var, *sub = NULL, *ret;

    if ((scan = strchr(value, '$')) == NULL) {
        return value;
    }

    if (*(scan + 1) == '\0') {
        return value;
    }

    buf = (char *)calloc(MAX_LINE, sizeof(char));
    if (!buf) {
        return NULL;
    }

    if (scan - value > avail) {
        goto error;
    }

    strncpy(buf, value, scan - value);
    avail -= scan - value;

    ++scan;
    if (*scan == '{' || *scan == '(') {
        ++scan;
    }

    p = (char *)scan;
    while (*scan && *scan != '}' && *scan != ')' && *scan != ' ') {
        ++scan;
        ++len;
    }

    if (*scan == '}' || *scan == ')') {
        ++scan;
    }

    sub = str_sub(p, 0, len);
    if (!sub) {
        goto error;
    }

    if ((var = conf_get_str_value(conf, sub, NULL)) == NULL) {
        var = getenv(sub);
    }

    if (var) {
        if (strlen(var) > avail) {
            goto error;
        }
        strncat(buf, var, avail);
        avail -= strlen(var);
    }
    strncat(buf, scan, avail);
    free(sub);

    if ((ret = conf_evaluate(conf, buf)) == NULL) {
        goto error;
    } else if (ret == buf) {
        return ret;
    } else {
        free(buf);
        return ret;
    }

error:
    if (buf) free(buf);
    if (sub) free(sub);
    return NULL;
}

static int conf_parse(conf_t *conf, char *resolved_path, 
        FILE *fp, int block) {
    int n;
    int ret = 0;
    char buf[MAX_LINE] = {};
    unsigned char *field[2];
    conf_value_t *cv;
    char *var = NULL;

    if (!conf->ht) {
        conf->ht = hash_create(HASH_INIT_SLOTS);
        if (!conf->ht) {
            perror("hash_create failed");
            return -1;
        }

        HASH_SET_KEYCPY(conf->ht, key_dup);
        HASH_SET_FREE_KEY(conf->ht, free_key);
        HASH_SET_FREE_VAL(conf->ht, free_val);
        HASH_SET_KEYCMP(conf->ht, key_cmp);
    }
 
    while (fgets(buf, MAX_LINE, fp)) {
        n = strlen(buf);
        if (n == 0) {
            continue;
        }

        if (buf[n - 1] == '\n') {
            buf[n - 1] = '\0';
        }

        if (*buf == '#') {
            continue;
        } else if (str_explode(NULL, (unsigned char*)buf, field, 2) == 2) {
            int is_block = 0;

            if ((var = conf_evaluate(conf, (char *)field[1])) == NULL) {
                ret = -1;
                goto error;
            }

            /* Process `include' directive. */
            if (!strcmp((char *)field[0], "include")) {
                if (conf_parse_include(conf, resolved_path, var)) {
                    if (var != (char *)field[1]) {
                        free(var);
                    }
                    ret = -1;
                    goto error;
                }

                if (var != (char *)field[1]) {
                    free(var);
                }
                continue;
            }
            
            if (!strcmp((char *)field[1], "{")) {
                is_block = 1;   /* meet a block */
            }

            /* process a key/value config */
            cv = (conf_value_t*)hash_get_val(conf->ht, (void *)field[0]);
            if (!cv) {
                /* Add a conf value */
                cv = calloc(1, sizeof(conf_value_t));
                if (!cv) {
                    ret = -1;
                    goto error;
                }

                if (hash_insert(conf->ht, (void *)field[0], cv) != 0) {
                    free(cv);
                    ret = -1;
                    goto error;
                }
 
                if (is_block) {
                    conf_block_t *cb = NULL;
                    cb = calloc(1, sizeof(conf_block_t));
                    if (!cb) {
                        ret = -1;
                        goto error;
                    }

                    if (conf_parse(&cb->block, resolved_path, fp, 1) != 0) {
                        free(cb);
                        ret = -1;
                        goto error;
                    }
                    cb->next = NULL;
                    cv->type = CONF_TYPE_BLOCK;
                    cv->value = (void *)cb;
                } else {
                    conf_entry_t *ce = NULL;
                    ce = calloc(1, sizeof(conf_entry_t));
                    if (!ce) {
                        ret = -1;
                        goto error;
                    }
                    ce->value = (var == (char *)field[1]) ?
                        strdup((char *)field[1]) : var;
                    ce->next = NULL;
                    cv->type = CONF_TYPE_ENTRY;
                    cv->value = ce;
                }
            } else {
                if (cv->type == CONF_TYPE_ENTRY) {
                    conf_entry_t *ce;
                    if (is_block) {
                        ret = -1;
                        goto error;
                    }

                    ce = calloc(1, sizeof(conf_entry_t));
                    if (!ce) {
                        ret = -1;
                        goto error;
                    }

                    ce->value = (var == (char *)field[1]) ?
                        strdup((char *)field[1]) : var;
                    ce->next = (conf_entry_t*)(cv->value);
                    cv->value = ce;
                } else {
                    conf_block_t *cb = NULL;
                    if (!is_block) {
                        ret = -1;
                        goto error;
                    }

                    cb = calloc(1, sizeof(conf_block_t));
                    if (!cb) {
                        ret = -1;
                        goto error;
                    }

                    if (conf_parse(&cb->block, resolved_path, fp, 1) != 0) {
                        free(cb);
                        ret = -1;
                        goto error;
                    }
                    cb->next = (conf_block_t *)(cv->value);
                    cv->value = cb;
                }
            }
        } else {
            if (field[0] && field[0][0] == '}') {
                if (block) {
                    return 0;   /* parse block over */
                } else {
                    ret = -1;
                    goto error;
                }
            }
        }
    }

error:
    if (ret == -1) {
        conf_free(conf);
    }
    return ret;
}

/* Before calling this function first time, please
 * initialize the `conf_t' structure with zero. 
 * such as 'conf_t conf = {};' */
int conf_init(conf_t *conf, const char *filename) {
    FILE *fp;
    char resolved_path[PATH_MAX];

    if (!realpath(filename, resolved_path)) {
        fprintf(stderr, "%s\n", strerror(errno));
        return -1;
    }

    if (!(fp = fopen(filename, "r"))) {
        perror("fopen failed");
        return -1;
    }

    if (conf_parse(conf, resolved_path, fp, 0) != 0) {
        fclose(fp);
        return -1;
    } 
    fclose(fp);
    return 0;
}


void conf_free(conf_t *conf) {
    hash_free(conf->ht);
}

/* When key not found in conf, default value was returned. */
int conf_get_int_value(conf_t *conf, const char *key, int def) {
    conf_entry_t *ce;
    conf_value_t *cv = (conf_value_t*)hash_get_val(conf->ht, key);

    if (!cv) {
        return def;
    }

    if (cv->type == CONF_TYPE_BLOCK) {
        return def;
    } else if (cv->type == CONF_TYPE_ENTRY) {
        ce = (conf_entry_t *)cv->value;
    } else {
        return def;
    }

    if (ce) {
        return str2int(ce->value, def);
    }

    return def;
}

/* When key not found in conf, default value was returned. */
char * conf_get_str_value(conf_t *conf, const char *key, 
        char *def) {
    conf_entry_t *ce;
    conf_value_t *cv = (conf_value_t*)hash_get_val(conf->ht, key);

    if (!cv) {
        return def;
    }

    if (cv->type == CONF_TYPE_BLOCK) {
        return def;
    } else if (cv->type == CONF_TYPE_ENTRY) {
        ce = (conf_entry_t *)cv->value;
    } else {
        return def;
    }

    if (ce) {
        return ce->value;
    }

    return def;
}

conf_block_t *conf_get_block(conf_t *conf, char *key) {
    conf_value_t *cv = (conf_value_t *)hash_get_val(conf->ht, key);
    if (!cv) {
        return NULL;
    }

    if (cv->type != CONF_TYPE_BLOCK) {
        return NULL;
    }

    return (conf_block_t *)(cv->value);
}

int conf_block_foreach(conf_t *conf, char *key,
        int (*foreach)(void *key, conf_block_t* block, void *userptr),
        void *userptr) {
    conf_block_t *cb, *next;
    conf_value_t *cv = (conf_value_t *)hash_get_val(conf->ht, key);
    if (!cv) {
        return -1;
    }

    if (cv->type != CONF_TYPE_BLOCK) {
        return -1;
    }

    cb = (conf_block_t *)cv->value;
    while (cb) {
        next = cb->next;
        if (foreach(key, cb, userptr) != 0) {
            return -1;
        }
        cb = next;
    }

    return 0;
}

int conf_array_foreach(conf_t *conf,
        char *key,
        int (*foreach)(void *key, void *value, void *userptr),
        void *userptr) {
    conf_entry_t *ce, *next;
    conf_value_t *cv = (conf_value_t*)hash_get_val(conf->ht, key);

    if (!cv) {
        return 0;
    }

    if (cv->type == CONF_TYPE_BLOCK) {
        return -1;
    } else if (cv->type == CONF_TYPE_ENTRY) {
        ce = (conf_entry_t *)cv->value;
        while (ce) {
            next = ce->next;
            if (foreach(key, ce->value, userptr) != 0) {
                return -1;
            }
            ce = next;
        }
        return 0;
    } else {
        return -1;
    }
}

static int print_block_conf(void *key, conf_block_t *cb, void *userptr) {
    printf("%s {\n", (char *)key);
    conf_dump(&cb->block);
    printf("}\n");
    return 0;
}

static int print_conf(void *key, void *value, void *userptr) {
    printf("%-20s %-30s\n", (char *)key, (char *)value);
    return 0;
}

static int conf_print_foreach(const hash_entry_t *he, void *userptr) {
    conf_value_t * cv = (conf_value_t*)he->val;
    if (cv->type == CONF_TYPE_ENTRY) {
        return conf_array_foreach((conf_t*)userptr, he->key,  
                print_conf, NULL);
    } else if (cv->type == CONF_TYPE_BLOCK) {
        return conf_block_foreach((conf_t*)userptr, he->key,
                print_block_conf, NULL);
    } else {
        return 0;
    }
}

void conf_dump(conf_t *conf) {
    hash_foreach(conf->ht, conf_print_foreach, (void *)conf);
}

#ifdef CONF_TEST_MAIN
/* gcc conf.c hash.c -DCONF_TEST_MAIN -I../inc */
int main(int argc, char *argv[]) {
    conf_t   conf = {};

    if (argc < 2) {
        fprintf(stderr, "usage: ./a.out <conf_file>\n");
        exit(1);
    }

    if (conf_init(&conf, argv[1]) != 0) {
        fprintf(stderr, "conf_init error\n");
        exit(1);
    }
    conf_dump(&conf);

    printf("PORT: %d\n", conf_get_int_value(&conf, "porta", 7777));
    printf("LOG_NAME: %s\n", conf_get_str_value(&conf, "log_name", "NULL"));

    conf_free(&conf);
    exit(0);
}
#endif /* CONF_TEST_MAIN */
