#include "myutils.h"
#include <stdio.h>

uint32_t cpu_myutils_digtoval(char c)
{
	if ((c>='0') && (c<='9'))
		return c-'0';
	if ((c>='a') && (c<='f'))
		return c-'a' + 10;
	if ((c>='A') && (c<='F'))
		return c-'A' + 10;
			
	return 0;
}

void cpu_myutils_hex2bytes(const char* str, uint8_t* output, int nbytes)
{
    int j = 0;	
	int i=0;
	while(j < nbytes)
	{
		uint8_t v = cpu_myutils_digtoval(str[i])*16 + cpu_myutils_digtoval(str[i+1]);
		output[j] = v;
        j++;
		i+=2;
	}		
}

void cpu_myutils_print_mem(const void* memory, uint32_t n)
{
	const unsigned char* input = (const unsigned char*) memory;
	for(uint32_t i=0; i<n; i++)
		printf("%02X", input[i]);
	printf("\n");
}
