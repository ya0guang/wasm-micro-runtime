/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_vmcore.h"
#include <platform_api_vmcore.h>
#include <platform_api_extension.h>

int
bh_platform_init()
{
    return 0;
}

void
bh_platform_destroy()
{
}

int
os_printf(const char *format, ...)
{
    int ret = 0;
    va_list ap;

    va_start(ap, format);
#ifndef BH_VPRINTF
    // ya0guang: also nullify here
    return NULL;
    // ret += vprintf(format, ap);
#else
    ret += BH_VPRINTF(format, ap);
#endif
    va_end(ap);

    return ret;
}

int
os_vprintf(const char *format, va_list ap)
{
#ifndef BH_VPRINTF
    // ya0guang: nullify printf
    return 0;
    // return vprintf(format, ap);
#else
    return BH_VPRINTF(format, ap);
#endif
}

// ya0guang: nullify this implementation 
uint8 *os_thread_get_stack_boundary(void)
{
    return NULL;
}

// functions below are copied from the common library

void *
os_malloc(unsigned size)
{
    return malloc(size);
}

void *
os_realloc(void *ptr, unsigned size)
{
    return realloc(ptr, size);
}

void
os_free(void *ptr)
{
    free(ptr);
}

int os_mutex_destroy(korp_mutex *mutex)
{
    int ret;

    assert(mutex);
    ret = pthread_mutex_destroy(mutex);

    return ret == 0 ? BHT_OK : BHT_ERROR;
}


int os_mutex_unlock(korp_mutex *mutex)
{
    int ret;

    assert(mutex);
    ret = pthread_mutex_unlock(mutex);

    return ret == 0 ? BHT_OK : BHT_ERROR;
}

int os_mutex_lock(korp_mutex *mutex)
{
    int ret;

    assert(mutex);
    ret = pthread_mutex_lock(mutex);

    return ret == 0 ? BHT_OK : BHT_ERROR;
}

int os_mutex_init(korp_mutex *mutex)
{
    return pthread_mutex_init(mutex, NULL) == 0 ? BHT_OK : BHT_ERROR;
}

uint64
os_time_get_boot_microsecond()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }

    return ((uint64) ts.tv_sec) * 1000 * 1000 + ((uint64)ts.tv_nsec) / 1000;
}


korp_tid os_self_thread()
{
    return (korp_tid) pthread_self();
}
