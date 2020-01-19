#include <stdio.h>
#include "cuda_helper.h"

extern int opt_n_threads;

void cuda_log_lasterror(int thr_id, const char* func, int line);
void cuda_clear_lasterror();
int cuda_num_devices();

#define CUDA_LOG_ERROR() cuda_log_lasterror(thr_id, __func__, __LINE__)

namespace gpu {
void utils_print_mem(const void* memory, uint32_t n);
void utils_hex2bytes(const char* str, uint8_t* output, int nbytes);

}
