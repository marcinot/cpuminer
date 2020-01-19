#include <stdint.h>
#include <string.h>
#include <gmp.h>




#ifdef __cplusplus
extern "C" {  
#endif

uint32_t biblepay_process_x11_80(int gpu_device, int thr_id, uint32_t num_hashes, uint8_t* hashes,
	uint8_t* input_template,
	uint32_t startNonce,
	int addAlgo
);

#ifdef __cplusplus
}
#endif



static const char* b[31102];
static bool b_initialized = false;


void additional_kjv_init(const char* b[31102]);

void initkjv()
{
	if (!b_initialized)
	{		
		additional_kjv_init(b);
		b_initialized = true;
	}
}	


struct BibleHash_Context {
	mpz_t maxv;
	mpz_t v0;

	BibleHash_Context()
	{
		mpz_init_set_str(maxv, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16);	
		mpz_init(v0);
	}

	~BibleHash_Context()
	{
		mpz_clear(maxv);
		mpz_clear(v0);
	}
};


void biblehash_v2_gpu_divide(uint8_t h[32], int64_t nDivisor, BibleHash_Context* ctx)
{
	void* v0_mem = mpz_limbs_write(ctx->v0, 4);
	memcpy(v0_mem, h, 32);
	mpz_limbs_finish(ctx->v0, 4);
  	mpz_mul_ui(ctx->v0, ctx->v0, 420);  	
	mpz_and(ctx->v0, ctx->v0, ctx->maxv);
  	mpz_fdiv_q_ui(ctx->v0, ctx->v0, nDivisor);  	
	const void* v0_mem_2 = mpz_limbs_read(ctx->v0);
	memcpy(h, v0_mem_2, 32);
}

bool quick_divide_and_test(uint8_t hash[32], uint64_t nDivisor, uint64_t target, uint32_t thread)
{
	uint64_t* hash64 = (uint64_t*) hash;
	uint64_t v = hash64[3];
	v = v * 420;
	v = v / nDivisor;
	return (v < target );
}

#ifdef __cplusplus
extern "C" {  
#endif

uint32_t biblehash_v2_gpu(int gpu_device, int batchSize, uint8_t* hashes, char* begin, uint32_t startNonce, bool fLate)
{
	BibleHash_Context ctx;
	int64_t nDivisor = fLate ? 8400 : 1777;	
    initkjv();	
	uint32_t candidate_idx = biblepay_process_x11_80(gpu_device, gpu_device, batchSize, hashes, (uint8_t*)begin, startNonce, 5);
	

	if (candidate_idx != 0xffffffff)		
		{			
			uint8_t* myhash = hashes + candidate_idx*64;
			if (quick_divide_and_test(myhash, nDivisor, 0x00000000FFFFFFFFUL, candidate_idx))
			{
				biblehash_v2_gpu_divide(myhash, nDivisor, &ctx );
				memset(myhash + 32, 0, 32);	
			} else {
				memset(myhash, 0xFF, 32);
				memset(myhash + 32, 0, 32);	
			}

		}

	return candidate_idx;
}

#ifdef __cplusplus
}
#endif
