#include <stdio.h>
#include <unistd.h>
#include "../../include/logger.h"

void log_performance(const char *op, struct timeval *start, struct timeval *end, struct rusage *usage_start, struct rusage *usage_end) {
    long seconds = end->tv_sec - start->tv_sec;
    long micros = end->tv_usec - start->tv_usec;
    double elapsed = seconds + micros*1e-6;

    long u_sec = usage_end->ru_utime.tv_sec - usage_start->ru_utime.tv_sec;
    long u_usec = usage_end->ru_utime.tv_usec - usage_start->ru_utime.tv_usec;
    double user_cpu = u_sec + u_usec*1e-6;

    long s_sec = usage_end->ru_stime.tv_sec - usage_start->ru_stime.tv_sec;
    long s_usec = usage_end->ru_stime.tv_usec - usage_start->ru_stime.tv_usec;
    double sys_cpu = s_sec + s_usec*1e-6;

    FILE *fp = fopen("encfs_perf.log", "a");
    if (fp) {
        fprintf(fp, "Op: %s, Latency: %.6f s, UserCPU: %.6f s, SysCPU: %.6f s\n", 
                op, elapsed, user_cpu, sys_cpu);
        fclose(fp);
    }
}
