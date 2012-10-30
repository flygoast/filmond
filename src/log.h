#ifndef __LOG_H_INCLUDED__
#define __LOG_H_INCLUDED__

#define LOG_LEVEL_FATAL     0
#define LOG_LEVEL_ERROR     1
#define LOG_LEVEL_WARNING   2
#define LOG_LEVEL_NOTICE    3
#define LOG_LEVEL_DEBUG     4
#define LOG_LEVEL_ALL       LOG_LEVEL_DEBUG

#define LOG_FILE_SIZE       (1 << 30)
#define LOG_MULTI_NO        0
#define LOG_MULTI_YES       1
#define LOG_FILE_NUM        10

#define DETAIL(level, fmt, args...) \
    log_write(level, "[%s:%d:%s]" fmt, __FILE__, __LINE__, \
        __FUNCTION__, ##args)

#define SIMPLY(level, fmt, args...) \
    log_write(level, fmt, ##args);

#define FATAL_LOG(fmt, args...) DETAIL(LOG_LEVEL_FATAL, fmt, ##args)
#define ERROR_LOG(fmt, args...) DETAIL(LOG_LEVEL_ERROR, fmt, ##args)
#define WARNING_LOG(fmt, args...) DETAIL(LOG_LEVEL_WARNING, fmt, ##args)
#define NOTICE_LOG(fmt, args...) DETAIL(LOG_LEVEL_NOTICE, fmt, ##args)
#ifdef DEBUG
#define DEBUG_LOG(fmt, args...) DETAIL(LOG_LEVEL_DEBUG, fmt, ##args)
#else
#define DEBUG_LOG(fmt, args...) /* nothing */
#endif

#define BOOT_OK(fmt, args...) boot_notify(0, fmt, ##args)
#define BOOT_FAILED(fmt, args...) do { \
    boot_notify(-1, fmt, ##args); \
    exit(1); \
} while (0) 

extern void boot_notify(int ok, const char *fmt, ...);
extern int log_init(const char *dir, const char *filename, 
        int level, int size, int n, int multi);
extern void log_write(int level, const char *fmt, ...);
extern void log_close();

#endif /* __LOG_H_INCLUDED__ */
