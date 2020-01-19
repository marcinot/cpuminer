#include "cuda_helper.h"

__device__  void gpu_utils_print_mem(const void* memory, uint32_t n);

__device__ bool gpu_quick_divide_and_test(uint8_t hash[32], uint64_t nDivisor, uint64_t target)
{
	uint64_t* hash64 = (uint64_t*) hash;
	uint64_t v = hash64[3];

	v = v * 420;
	v = v / nDivisor;
	
	return (v < target );
}

__global__ void gpu_divide_test_all(int threads, uint8_t* hashes, uint32_t* candidate_idx)
{
	const uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads)
	{
        uint8_t* inp = hashes + thread * 64;
        if (gpu_quick_divide_and_test(inp, 1777, 0x00000000FFFFFFFFUL ))
        {     
			*candidate_idx = thread;
        }
	}
}

__host__ void cpu_divide_test_all(uint32_t num_hashes, uint8_t* hashes, uint32_t* candidate_idx)
{
	int threads = num_hashes;	
	const uint32_t threadsperblock = 256;
	dim3 grid((threads + threadsperblock-1)/threadsperblock);
	dim3 block(threadsperblock);
	gpu_divide_test_all <<<grid, block >>> (threads, hashes, candidate_idx);	
	CUDA_SAFE_CALL(cudaGetLastError());	
}
