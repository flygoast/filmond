#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "plugin.h"
#include "log.h"
#include "version.h"


static char     *moni_dir;
static mode_t    file_origin_mode;
static mode_t    file_target_mode;
static mode_t    dir_origin_mode;
static mode_t    dir_target_mode;


static int chmod_path(const char *path, const struct stat *st) {
    if (S_ISDIR(st->st_mode)) {
        if (dir_origin_mode == -1) {
            /*
             * just care for 'rwx' permissions
             */
            if ((st->st_mode & 0777) != dir_target_mode) {
                if (chmod(path, dir_target_mode) != 0) {
                    ERROR_LOG("chmod(\"%s\", %d) failed: %s", path, 
                        dir_target_mode, strerror(errno));
                    return FILMOND_DECLINED;
                }
            }
        } else {
            if ((st->st_mode & 0777) == dir_origin_mode) {
                if (chmod(path, dir_target_mode) != 0) {
                    ERROR_LOG("chmod(\"%s\", %d) failed: %s", path, 
                        dir_target_mode, strerror(errno));
                    return FILMOND_DECLINED;
                }
            }
        }
    } else {
        if (file_origin_mode == -1) {
            /*
             * just care for 'rwx' permissions
             */
            if ((st->st_mode & 0777) != file_target_mode) {
                if (chmod(path, file_target_mode) != 0) {
                    ERROR_LOG("chmod(\"%s\", %d) failed: %s", path, 
                        file_target_mode, strerror(errno));
                    return FILMOND_DECLINED;
                }
            }
        } else {
            if ((st->st_mode & 0777) == file_origin_mode) {
                if (chmod(path, file_target_mode) != 0) {
                    ERROR_LOG("chmod(\"%s\", %d) failed: %s", path, 
                        file_target_mode, strerror(errno));
                    return FILMOND_DECLINED;
                }
            }
        }
    }

    return FILMOND_DECLINED;
}


int plugin_file_ftw(const char *filepath, const struct stat *st) {
    char fullpath[PATH_MAX];
    int  ret;

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", moni_dir, filepath);
    if (ret >= PATH_MAX) {
        ERROR_LOG("file path is too long: %s", filepath);
        return FILMOND_DECLINED;
    }

    return chmod_path(fullpath, st);
}


int plugin_file_event(int action, char *filepath, char *moved_from) {
    struct stat     st;

    switch (action) {
    case ACTION_FILE_MODIFY:
    case ACTION_FILE_ATTRIB:
        if (stat(filepath, &st) < 0) {
            ERROR_LOG("stat %s failed:%s", filepath, strerror(errno));
            return FILMOND_DECLINED;
        }

        return chmod_path(filepath, &st);
    }

    return FILMOND_DECLINED;
}


int plugin_dir_ftw(const char *dirpath, const struct stat *st) {
    char fullpath[PATH_MAX];
    int  ret;

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", moni_dir, dirpath);
    if (ret >= PATH_MAX) {
        ERROR_LOG("file path is too long: %s", dirpath);
        return FILMOND_DECLINED;
    }

    return chmod_path(dirpath, st);
}


int plugin_dir_event(int action, char *dirpath, char *moved_from) {
    struct stat     st;

    switch (action) {
    case ACTION_DIR_ATTRIB:
    case ACTION_DIR_MODIFY:
        if (stat(dirpath, &st) < 0) {
            ERROR_LOG("stat %s failed:%s", dirpath, strerror(errno));
            return FILMOND_DECLINED;
        }
        return chmod_path(dirpath, &st);
    }

    return FILMOND_DECLINED;
}


int plugin_init(conf_t *conf) {
    moni_dir = conf_get_str_value(conf, "moni_dir", 
        "/usr/local/apache2/htdocs");
    file_origin_mode = conf_get_int_value(conf, "file_origin_mode", -1);
    file_target_mode = conf_get_int_value(conf, "file_target_mode", 0644);
    dir_origin_mode = conf_get_int_value(conf, "dir_origin_mode", -1);
    dir_target_mode = conf_get_int_value(conf, "dir_target_mode", 0755);

    return FILMOND_DECLINED;
}


void __chmod_plugin_main(void) {
    printf("*** filmond [chmod] plugin ***\n");
    printf("'chmod' plugin used to process invalid file permission\n");
    printf("filmond version: %s\n", FILMOND_VERSION);
    printf("%s\n", FILMOND_COPYRIGHT);
    exit(0);
}
