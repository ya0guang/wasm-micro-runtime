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

uint8 *os_thread_get_stack_boundary(void)
{
    return NULL;
}


