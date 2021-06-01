#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "stdint.h"
#include "stdbool.h"
#include "unistd.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_handle_command(unsigned int cmd, uint8_t* cmd_buf, unsigned int cmd_buf_size);
void ecall_iwasm_main(uint8_t* wasm_file_buf, uint32_t wasm_file_size);
int ecall_wamr_execute(uint8_t* input_file, int input_file_size, int argc, char** argv, char* errorbuf, char* output);

sgx_status_t SGX_CDECL ocall_print(const char* str);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);
sgx_status_t SGX_CDECL ocall_open(int* retval, const char* pathname, int flags, bool has_mode, unsigned int mode);
sgx_status_t SGX_CDECL ocall_openat(int* retval, int dirfd, const char* pathname, int flags, bool has_mode, unsigned int mode);
sgx_status_t SGX_CDECL ocall_close(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_read(ssize_t* retval, int fd, void* buf, size_t read_size);
sgx_status_t SGX_CDECL ocall_lseek(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL ocall_ftruncate(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL ocall_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_fdatasync(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_isatty(int* retval, int fd);
sgx_status_t SGX_CDECL ocall_fdopendir(int fd, void** p_dirp);
sgx_status_t SGX_CDECL ocall_readdir(void** retval, void* dirp);
sgx_status_t SGX_CDECL ocall_rewinddir(void* dirp);
sgx_status_t SGX_CDECL ocall_seekdir(void* dirp, long int loc);
sgx_status_t SGX_CDECL ocall_telldir(long int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_closedir(int* retval, void* dirp);
sgx_status_t SGX_CDECL ocall_stat(int* retval, const char* pathname, void* buf, unsigned int buf_len);
sgx_status_t SGX_CDECL ocall_fstat(int* retval, int fd, void* buf, unsigned int buf_len);
sgx_status_t SGX_CDECL ocall_fstatat(int* retval, int dirfd, const char* pathname, void* buf, unsigned int buf_len, int flags);
sgx_status_t SGX_CDECL ocall_mkdirat(int* retval, int dirfd, const char* pathname, unsigned int mode);
sgx_status_t SGX_CDECL ocall_link(int* retval, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL ocall_linkat(int* retval, int olddirfd, const char* oldpath, int newdirfd, const char* newpath, int flags);
sgx_status_t SGX_CDECL ocall_unlinkat(int* retval, int dirfd, const char* pathname, int flags);
sgx_status_t SGX_CDECL ocall_readlinkat(ssize_t* retval, int dirfd, const char* pathname, char* buf, size_t bufsiz);
sgx_status_t SGX_CDECL ocall_renameat(int* retval, int olddirfd, const char* oldpath, int newdirfd, const char* newpath);
sgx_status_t SGX_CDECL ocall_symlinkat(int* retval, const char* target, int newdirfd, const char* linkpath);
sgx_status_t SGX_CDECL ocall_ioctl(int* retval, int fd, unsigned long int request, void* arg, unsigned int arg_len);
sgx_status_t SGX_CDECL ocall_fcntl(int* retval, int fd, int cmd);
sgx_status_t SGX_CDECL ocall_fcntl_long(int* retval, int fd, int cmd, long int arg);
sgx_status_t SGX_CDECL ocall_realpath(int* retval, const char* path, char* buf, unsigned int buf_len);
sgx_status_t SGX_CDECL ocall_posix_fallocate(int* retval, int fd, off_t offset, off_t len);
sgx_status_t SGX_CDECL ocall_poll(int* retval, void* fds, unsigned int nfds, int timeout, unsigned int fds_len);
sgx_status_t SGX_CDECL ocall_getopt(int* retval, int argc, char* argv_buf, unsigned int argv_buf_len, const char* optstring);
sgx_status_t SGX_CDECL ocall_getrandom(ssize_t* retval, void* buf, size_t buflen, unsigned int flags);
sgx_status_t SGX_CDECL ocall_getentropy(int* retval, void* buffer, size_t length);
sgx_status_t SGX_CDECL ocall_readv(ssize_t* retval, int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset);
sgx_status_t SGX_CDECL ocall_writev(ssize_t* retval, int fd, char* iov_buf, unsigned int buf_size, int iovcnt, bool has_offset, off_t offset);
sgx_status_t SGX_CDECL ocall_clock_gettime(int* retval, unsigned int clock_id, void* tp_buf, unsigned int tp_buf_size);
sgx_status_t SGX_CDECL ocall_clock_getres(int* retval, int clock_id, void* res_buf, unsigned int res_buf_size);
sgx_status_t SGX_CDECL ocall_utimensat(int* retval, int dirfd, const char* pathname, const void* times_buf, unsigned int times_buf_size, int flags);
sgx_status_t SGX_CDECL ocall_futimens(int* retval, int fd, const void* times_buf, unsigned int times_buf_size);
sgx_status_t SGX_CDECL ocall_clock_nanosleep(int* retval, unsigned int clock_id, int flags, const void* req_buf, unsigned int req_buf_size, void* rem_buf, unsigned int rem_buf_size);
sgx_status_t SGX_CDECL ocall_raise(int* retval, int sig);
sgx_status_t SGX_CDECL ocall_sched_yield(int* retval);
sgx_status_t SGX_CDECL ocall_pthread_rwlock_init(int* retval, void** rwlock, void* attr);
sgx_status_t SGX_CDECL ocall_pthread_rwlock_destroy(int* retval, void* rwlock);
sgx_status_t SGX_CDECL ocall_pthread_rwlock_rdlock(int* retval, void* rwlock);
sgx_status_t SGX_CDECL ocall_pthread_rwlock_wrlock(int* retval, void* rwlock);
sgx_status_t SGX_CDECL ocall_pthread_rwlock_unlock(int* retval, void* rwlock);
sgx_status_t SGX_CDECL ocall_get_errno(int* retval);
sgx_status_t SGX_CDECL ocall_socket(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL ocall_getsockopt(int* retval, int sockfd, int level, int optname, void* val_buf, unsigned int val_buf_size, void* len_buf);
sgx_status_t SGX_CDECL ocall_sendmsg(ssize_t* retval, int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags);
sgx_status_t SGX_CDECL ocall_recvmsg(ssize_t* retval, int sockfd, void* msg_buf, unsigned int msg_buf_size, int flags);
sgx_status_t SGX_CDECL ocall_shutdown(int* retval, int sockfd, int how);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
