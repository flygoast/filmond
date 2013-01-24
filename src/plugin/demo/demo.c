#include <stdio.h>
#include <stdlib.h>
#include "plugin.h"
#include "log.h"
#include "version.h"


static char     *moni_dir;


int plugin_init(conf_t *conf) {
    DEBUG_LOG("demo plugin init");

    moni_dir = conf_get_str_value(conf, "moni_dir",
        "/usr/local/apache2/htdocs");

    DEBUG_LOG("monitor derectory: %s", moni_dir);

    return FILMOND_DECLINED;
}


int plugin_dir_ftw(const char *dirpath, const struct stat *st) {

    DEBUG_LOG("ftw directory: %s", dirpath);

    return FILMOND_DECLINED;
}


int plugin_file_ftw(const char *filepath, const struct stat *st) {

    DEBUG_LOG("ftw file: %s", filepath);

    return FILMOND_DECLINED;
}


int plugin_ftw_post() {

    DEBUG_LOG("%s ftw over", moni_dir);

    return FILMOND_DECLINED;
}


int plugin_dir_event(int action, char *fullpath, char *moved_from) {
    switch (action) {
    case ACTION_DIR_CREATE:
        DEBUG_LOG("DIR_CREATE: \"%s\"", fullpath);
        break;
    case ACTION_DIR_DELETE:
        DEBUG_LOG("DIR_DELETE: \"%s\"", fullpath);
        break;
    case ACTION_DIR_ATTRIB:
        DEBUG_LOG("DIR_ATTRIB: \"%s\"", fullpath);
        break;
    case ACTION_DIR_MODIFY:
        DEBUG_LOG("DIR_MODIFY: \"%s\"", fullpath);
        break;
    case ACTION_DIR_MOVE:
        DEBUG_LOG("DIR_MOVE: \"%s\"<-\"%s\"", fullpath, moved_from);
        break;
    default:
        return FILMOND_ERROR;
    }

    return FILMOND_DECLINED;
}


int plugin_file_event(int action, char *fullpath, char *moved_from) {
    switch (action) {
    case ACTION_FILE_CREATE:
        DEBUG_LOG("FILE_CREATE: \"%s\"", fullpath);
        break;
    case ACTION_FILE_DELETE:
        DEBUG_LOG("FILE_DELETE: \"%s\"", fullpath);
        break;
    case ACTION_FILE_ATTRIB:
        DEBUG_LOG("FILE_ATTRIB: \"%s\"", fullpath);
        break;
    case ACTION_FILE_MODIFY:
        DEBUG_LOG("FILE_MODIFY: \"%s\"", fullpath);
        break;
    case ACTION_FILE_MOVE:
        DEBUG_LOG("FILE_MOVE: \"%s\"<-\"%s\"", fullpath, moved_from);
        break;
    default:
        return FILMOND_ERROR;
    }

    return FILMOND_DECLINED;
}


int plugin_deinit(conf_t *conf) {

    DEBUG_LOG("demo plugin deinit");

    return FILMOND_DECLINED;
}


void __demo_plugin_main(void) {
    printf("*** filmond [demo] plugin ***\n");
    printf("'demo' plugin used as toturial for filmond plugin development\n");
    printf("filmond version: %s\n", FILMOND_VERSION);
    printf("%s\n", FILMOND_COPYRIGHT);
    exit(0);
}
