#include <stdio.h>
#include "miner.h"
#include <string.h>
//#include <vector>


// nonce array also used in other algos
uint32_t *heavy_nonceVector[MAX_GPUS];
char * device_name[MAX_GPUS];
short device_map[MAX_GPUS] = { 0 };
long  device_sm[MAX_GPUS] = { 0 };
short device_mpcount[MAX_GPUS] = { 0 };

short is_device_flags_set[MAX_GPUS] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

int opt_n_threads=0;

int device_check[MAX_GPUS] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };


void quark_blake512_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_outputHash, int order, int iter);
void quark_bmw512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);

void quark_groestl512_cpu_init(int thr_id, uint32_t threads);
void quark_groestl512_cpu_free(int thr_id);
void quark_groestl512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);

void quark_skein512_cpu_hash_64(int thr_id, const uint32_t threads, const uint32_t startNonce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);

void quark_jh512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);

void quark_keccak512_cpu_init(int thr_id, uint32_t threads);
void quark_keccak512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);

void quark_groestl512_sm20_init_bbp(int thr_id, uint32_t threads);
void biblepay_myhash_64_cpu(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order, int iter);


void quark_blake512_cpu_setBlock_80(int thr_id, uint32_t *endiandata, uint64_t* c_PaddedMessage80);
void quark_blake512_cpu_hash_80(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_outputHash, uint64_t* c_PaddedMessage80);

void x11_luffaCubehash512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t *d_hash, int order);
void x11_shavite512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);
void x11_shavite512_cpu_init(int thr_id, uint32_t threads);


int x11_simd512_cpu_init(int thr_id, uint32_t threads);
void x11_simd512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

void x11_echo512_cpu_init(int thr_id, uint32_t threads);
void x11_echo512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

void biblepay_noncevector_gen(uint32_t num_hashes, uint32_t* ghash_iterations, uint32_t* gnoncevector_all, uint32_t* gnoncevector_sizes);

void cpu_bibleencrypt_all(uint32_t num_hashes, uint8_t* hashes);

void cpu_md5_all(uint32_t num_hashes, uint8_t* hashes);

void cpu_kjv_md5_all(uint32_t num_hashes, uint8_t* hashes, char* kjv, uint16_t* kjv_len);

void cpu_sha256d_all(uint32_t num_hashes, uint8_t* hashes);

void cpu_divide_test_all(uint32_t num_hashes, uint8_t* hashes, uint32_t* candidate_hash);




thread_local char* kjv = NULL;
thread_local uint16_t* kjv_len = NULL;

void additional_kjv_init(const char* b[31102]);


#ifdef __cplusplus
extern "C" {  
#endif

void init_kjv_gpu_data(int gpu_device)
{	
	if (!kjv)
	{
		const int n = 31102;
		const int max_buff = 544;

		int total_size = n * max_buff;
		const char* b[n];
		uint16_t b_len[n];

		additional_kjv_init(b);

		CUDA_SAFE_CALL(cudaMalloc(&kjv, total_size));
		
		for(int i=0; i<n; i++)
		{
			b_len[i] = strlen(b[i]);
			int r = b_len[i] + 1;
			if (r > 544)
			{
				printf("r=%d\n", r);
				exit(-1);
			}

			CUDA_SAFE_CALL(cudaMemcpy(kjv + i * max_buff, b[i], r, cudaMemcpyHostToDevice));
		}

		CUDA_SAFE_CALL(cudaMalloc(&kjv_len, n*sizeof(uint16_t)));
		CUDA_SAFE_CALL(cudaMemcpy(kjv_len, b_len, n*sizeof(uint16_t), cudaMemcpyHostToDevice));
	}
}

int biblehash_cuda_num_devices()
{
	return cuda_num_devices();
}

thread_local uint8_t* ghashes = NULL;
thread_local uint64_t* c_PaddedMessage80 = NULL;
thread_local uint32_t* g_candidate_idx = NULL;

uint32_t biblepay_process_x11_80(int gpu_device, int thr_id, uint32_t num_hashes, uint8_t* hashes,
	uint8_t* input_template,
	uint32_t startNonce,
	int addAlgo
)
{	
	CUDA_SAFE_CALL(cudaSetDevice(gpu_device));
	
	if (is_device_flags_set[gpu_device]==0)
	{
		CUDA_SAFE_CALL(cudaSetDevice(gpu_device));
		is_device_flags_set[gpu_device] = 1;
		CUDA_SAFE_CALL(cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync));		
	}

	init_kjv_gpu_data(gpu_device);

	if (ghashes == NULL)
	{				
		CUDA_SAFE_CALL(cudaMalloc(&ghashes, num_hashes*64));
		x11_simd512_cpu_init(thr_id, num_hashes);
	}

	if (c_PaddedMessage80 == NULL)
	{			
		CUDA_SAFE_CALL(cudaMalloc(&c_PaddedMessage80, 16*sizeof(uint64_t)));
	}

	if (g_candidate_idx == NULL)
	{			
		CUDA_SAFE_CALL(cudaMalloc(&g_candidate_idx, 4));
	}

	CUDA_SAFE_CALL(cudaMemset(g_candidate_idx, 0xFF, 4));



	
	quark_blake512_cpu_setBlock_80(thr_id, (uint32_t*) input_template, c_PaddedMessage80);


	quark_blake512_cpu_hash_80(thr_id, num_hashes, startNonce, (uint32_t*)ghashes, c_PaddedMessage80);
	quark_bmw512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0, 0);	
	quark_groestl512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0, 0);
	quark_skein512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0, 0);
	quark_jh512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0, 0);
	quark_keccak512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0, 0);
	x11_luffaCubehash512_cpu_hash_64(thr_id, num_hashes, (uint32_t*)ghashes, 0);
	x11_shavite512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0);
	x11_simd512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0);
	x11_echo512_cpu_hash_64(thr_id, num_hashes, 0, NULL, (uint32_t*)ghashes, 0);	

	if (addAlgo>0)
	{
		cpu_bibleencrypt_all(num_hashes, ghashes );
	}
	if (addAlgo>1)
	{
		cpu_md5_all(num_hashes, ghashes);
	}
	if (addAlgo>2)
	{
		cpu_kjv_md5_all(num_hashes, ghashes, kjv, kjv_len);
	}

	if (addAlgo>3)
	{
		cpu_sha256d_all(num_hashes, ghashes);
	}



	uint32_t candidate_idx = 0xffffffff;
	if (addAlgo>4)
	{
		cpu_divide_test_all(num_hashes, ghashes, g_candidate_idx);	
		CUDA_SAFE_CALL(cudaThreadSynchronize());					
		CUDA_SAFE_CALL(cudaMemcpy(&candidate_idx, g_candidate_idx, sizeof(uint32_t), cudaMemcpyDeviceToHost));
	
		if (candidate_idx != 0xffffffff)
		{
			CUDA_SAFE_CALL(cudaMemcpy(hashes + candidate_idx * 64 , ghashes + candidate_idx * 64, 64, cudaMemcpyDeviceToHost));
		}

	
	} else {

		CUDA_SAFE_CALL(cudaMemcpy(hashes, ghashes, num_hashes * 64, cudaMemcpyDeviceToHost));
	}

	return candidate_idx;
}


#ifdef __cplusplus
}
#endif