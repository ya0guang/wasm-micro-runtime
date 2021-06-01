#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include "wasm_export.h"
#include <fcntl.h>

// steal from `bh_read_file_to_buffer`

char*
read_file_to_buffer(const char *filename, int *ret_size)
{
    char *buffer;
    int file;
    int file_size, buf_size, read_size;
    struct stat stat_buf;

    if (!filename || !ret_size) {
        printf("Read file to buffer failed: invalid filename or ret size.\n");
        return NULL;
    }

    if ((file = open(filename, O_RDONLY, 0)) == -1) {
        printf("Read file to buffer failed: open file %s failed.\n",
               filename);
        return NULL;
    }

    if (fstat(file, &stat_buf) != 0) {
        printf("Read file to buffer failed: fstat file %s failed.\n",
               filename);
        close(file);
        return NULL;
    }

    file_size = (int)stat_buf.st_size;

    /* At lease alloc 1 byte to avoid malloc failed */
    buf_size = file_size > 0 ? file_size : 1;

    if (!(buffer = malloc(buf_size))) {
        printf("Read file to buffer failed: alloc memory failed.\n");
        close(file);
        return NULL;
    }
#if WASM_ENABLE_MEMORY_TRACING != 0
    printf("Read file, total size: %u\n", file_size);
#endif

    read_size = (int)read(file, buffer, file_size);
    close(file);

    if (read_size < file_size) {
        printf("Read file to buffer failed: read file content failed.\n");
        BH_FREE(buffer);
        return NULL;
    }

    *ret_size = file_size;
    return buffer;
}

int main(int argc, char const *argv[])
{
    // int should be uint32 in Rust!
    char* file_buffer;
    int file_size;
    void* module;
    void* module_instance;
    char error_buffer[128];
    int stack_size = 8092, heap_size = 8092;

    for(int i = 0; i < argc; i++) {
        printf("arg %d: %s\n", i, argv[i]);
    }
    /* initialize the wasm runtime by default configurations */
    wasm_runtime_init();

    /* read WASM file into a memory buffer */
    file_buffer = read_file_to_buffer(argv[1], &file_size);
    printf("buffer: %p\n", file_buffer);

    // /* add line below if we want to export native functions to WASM app */
    // wasm_runtime_register_natives(...);

    /* parse the WASM file from buffer and create a WASM module */
    module = (void*)wasm_runtime_load(file_buffer, file_size, error_buffer, sizeof(error_buffer));
    printf("module: %p\n", module);

    /* create an instance of the WASM module (WASM linear memory is ready) */
    module_instance = (void*)wasm_runtime_instantiate(module, stack_size, heap_size, error_buffer, sizeof(error_buffer));
    printf("module_instance: %p\n", module_instance);


    // /*Call the main function of the WASM*/
    // int wasm_argc = 2;
    // int wasm_argv[2] = {3, 4};
    // int ret = (int)wasm_application_execute_main(module_instance, wasm_argc, wasm_argv);
    // printf("ret: %d\n", ret);
    // printf("argv: %d, %d\n", wasm_argv[0], wasm_argv[1]);



    int wasm_argc = 2;
    int wasm_argv[2] = {4, 5};
    // lookup a WASM function by its name. 
    // The function signature can NULL here
    void* func = wasm_runtime_lookup_function(module_instance, "entrypoint", NULL);
    printf("func: %p\n", func);

    // creat a excution environment which can be used by executing WASM functions
    void* exec_env = wasm_runtime_create_exec_env(module_instance, stack_size);
    printf("exec_env: %p\n", exec_env);

    if (wasm_runtime_call_wasm(exec_env, func, wasm_argc, wasm_argv) ) {
        /* the return value is stored in argv[0] */
        printf("add function return: %d\n", wasm_argv[0]);
    }
    else {
        printf("%s\n", wasm_runtime_get_exception(module_instance));
    }


}
