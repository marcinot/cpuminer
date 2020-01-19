#ifndef MY_UTILS_H
#define MY_UTILS_H

#include <stdint.h>

uint32_t cpu_myutils_digtoval(char c);
void cpu_myutils_hex2bytes(const char* str, uint8_t* output, int nbytes);
void cpu_myutils_print_mem(const void* memory, uint32_t n);

#endif
