/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _PLATFORM_INTERNAL_H
#define _PLATFORM_INTERNAL_H

#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <sgx_thread.h>
#include <pthread.h>

#include "sgx_error.h"
#include "wasm_export.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifndef BH_PLATFORM_LINUX_SGX
#define BH_PLATFORM_LINUX_SGX
#endif

#define _STACK_SIZE_ADJUSTMENT (32 * 1024)

/* Stack size of applet threads's native part.  */
#define BH_APPLET_PRESERVED_STACK_SIZE      (8 * 1024 + _STACK_SIZE_ADJUSTMENT)

/* Default thread priority */
#define BH_THREAD_DEFAULT_PRIORITY 0

typedef pthread_t korp_thread;
typedef pthread_t korp_tid;
typedef pthread_mutex_t korp_mutex;
typedef pthread_cond_t korp_cond;

typedef void (*os_print_function_t)(const char* message);
void os_set_print_function(os_print_function_t pf);

char *strcpy(char *dest, const char *src);

#ifdef __cplusplus
}
#endif

/* Teaclave protected file system */
uint32_t c_open_input(char* fid, int* out_handle);

uint32_t teaclave_open(wasm_exec_env_t exec_env, char* fid, int* dummy);

#endif /* end of _PLATFORM_INTERNAL_H */

