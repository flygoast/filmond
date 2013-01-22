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
static mode_t    target_mode;


static int chmod_file(char *filepath, const struct stat *st) {
    char    fullpath[PATH_MAX];
    int     ret;

    ret = snprintf(fullpath, PATH_MAX, "%s/%s", moni_dir, filepath);

    if (ret >= PATH_MAX) {
        ERROR_LOG("file path is too long: %s", filepath);
        return FILMOND_DECLINED;
    }

    if (st->st_mode != target_mode) {
        if (chmod(fullpath, target_mode) != 0) {
            ERROR_LOG("chmod(\"%s\", %d) failed: %s", filepath, target_mode,
                strerror(errno));
            return FILMOND_DECLINED;
        }
    }

    return FILMOND_DECLINED;
}


int plugin_file_ftw(char *filepath, const struct stat *st) {
    return chmod_file(filepath, st);
}


int plugin_file_event(int action, char *filepath, const struct stat *st) {
    if (action == ACTION_DEL) {
        return FILMOND_DECLINED;
    }

    return chmod_file(filepath, st);
}


int plugin_init(conf_t *conf) {
    moni_dir = conf_get_str_value(conf, "moni_dir", 
        "/usr/local/apache2/htdocs");
    target_mode = conf_get_int_value(conf, "chmod_mode", 0600);

    return FILMOND_DECLINED;
}


void __chmod_plugin_main(void) {
    printf("*** filmond [chmod] plugin ***\n");
    printf("'chmod' plugin used to process invalid file permission\n");
    printf("filmond version: %s\n", FILMOND_VERSION);
    printf("%s\n", FILMOND_COPYRIGHT);
    exit(0);
}
