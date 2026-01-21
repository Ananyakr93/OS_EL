#ifndef ENCFS_LOGGER_H
#define ENCFS_LOGGER_H

#include <sys/time.h>
#include <sys/resource.h>

void log_performance(const char *op, struct timeval *start, struct timeval *end, struct rusage *usage_start, struct rusage *usage_end);

#endif
