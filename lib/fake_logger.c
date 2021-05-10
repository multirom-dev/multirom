#include <stdlib.h>

#define LOG_BUF_MAX 51200
extern void multirom_klog_write(int level, const char* fmt, ...);
extern void multirom_klog_set_level(int level);
#define INFO(tag, fmt, ...) multirom_klog_write(6, "<6>%s: " fmt, tag, ##__VA_ARGS__)

int __android_log_print(int prio, const char* tag, const char* fmt, ...) {

    char buf[LOG_BUF_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    buf[LOG_BUF_MAX - 1] = 0;
    INFO(tag, "%s", buf);
    return 0;
}
