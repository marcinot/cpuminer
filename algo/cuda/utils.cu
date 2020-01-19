#include <stdint.h>
#include <stdio.h>


__device__  uint32_t gpu_utils_digtoval(char c)
{
	if ((c>='0') && (c<='9'))
		return c-'0';
	if ((c>='a') && (c<='f'))
		return c-'a' + 10;
	if ((c>='A') && (c<='F'))
		return c-'A' + 10;
			
	return 0;
}

__device__  void gpu_utils_hex2bytes(const char* str, uint8_t* output, int nbytes)
{
    int j = 0;	
	int i=0;
	while(j < nbytes)
	{
		uint8_t v = gpu_utils_digtoval(str[i])*16 + gpu_utils_digtoval(str[i+1]);
		output[j] = v;
        j++;
		i+=2;
	}		
}

__device__  void gpu_utils_print_mem(const void* memory, uint32_t n)
{
	const unsigned char* input = (const unsigned char*) memory;
	for(uint32_t i=0; i<n; i++)
		printf("%02X", input[i]);
	printf("\n");
}

