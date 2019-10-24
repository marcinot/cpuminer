#include "miner.h"
#include "kjv.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
extern bool fDebug;

void x11hash(void *output, const void *input)
{
	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;

	sph_luffa512_context     ctx_luffa1;
	sph_cubehash512_context  ctx_cubehash1;
	sph_shavite512_context   ctx_shavite1;
	sph_simd512_context      ctx_simd1;
	sph_echo512_context      ctx_echo1;

	uint32_t hashA[16] __attribute__((aligned(64)));
	uint32_t hashB[16] __attribute__((aligned(64)));

	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, 80);
	sph_blake512_close (&ctx_blake, hashA);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, hashA, 64);
	sph_bmw512_close(&ctx_bmw, hashB);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hashB, 64);
	sph_groestl512_close(&ctx_groestl, hashA);

	sph_skein512_init(&ctx_skein);
	sph_skein512 (&ctx_skein, hashA, 64);
	sph_skein512_close (&ctx_skein, hashB);

	sph_jh512_init(&ctx_jh);
	sph_jh512 (&ctx_jh, hashB, 64);
	sph_jh512_close(&ctx_jh, hashA);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, hashA, 64);
	sph_keccak512_close(&ctx_keccak, hashB);

	sph_luffa512_init (&ctx_luffa1);
	sph_luffa512 (&ctx_luffa1, hashB, 64);
	sph_luffa512_close (&ctx_luffa1, hashA);

	sph_cubehash512_init (&ctx_cubehash1);
	sph_cubehash512 (&ctx_cubehash1, hashA, 64);
	sph_cubehash512_close(&ctx_cubehash1, hashB);

	sph_shavite512_init (&ctx_shavite1);
	sph_shavite512 (&ctx_shavite1, hashB, 64);
	sph_shavite512_close(&ctx_shavite1, hashA);

	sph_simd512_init (&ctx_simd1);
	sph_simd512 (&ctx_simd1, hashA, 64);
	sph_simd512_close(&ctx_simd1, hashB);

	sph_echo512_init (&ctx_echo1);
	sph_echo512 (&ctx_echo1, hashB, 64);
	sph_echo512_close(&ctx_echo1, hashA);

	memcpy(output, hashA, 32);
}


static void R256b(uint8_t toSwap[], uint8_t swapped[])
{
	for (int i = 0; i < 32; i++)
	{
		int iSource = 31 - i;
		swapped[i] = toSwap[iSource];
	}
}

static void ConvertH32TO8sz(uint32_t h1[], uint8_t h2[], int total_size)
{
	for (int i = 0; i < total_size; i++)
	{
		uint32_t a1 = h1[i];
		memcpy(h2 + (i*4), &a1, sizeof(a1));
	}
}

static void ConvertH32TO8(uint32_t h1[], uint8_t h2[])
{
	for (int i = 0; i < 8; i++)
	{
		uint32_t a1 = h1[i];
		memcpy(h2 + (i*4), &a1, sizeof(a1));
	}
}

static void ConvertH8TO32(uint8_t h1[], uint32_t h2[])
{
	int v = 0;
	for (int i = 0; i < 8; i++)
	{
		v = i * 4;
		uint32_t i32 = (h1[v+3] << 24) | (h1[v+2] << 16) | (h1[v+1] << 8) | h1[v+0];
		h2[i] = i32;
	}
}

void printme2(char *caption, uint32_t bufhash[])
{
	uint32_t hash_be[8];
	char hash_str[65], target_str[65];
	for (int i = 0; i < 8; i++) 
	{
	    be32enc(hash_be + i, bufhash[7 - i]);
	}
	bin2hex(hash_str, (unsigned char *)hash_be, 32);
	printf("\n!! %s - HASH [%s] \n", caption, hash_str);
}

static void becencode(uint32_t bufhash[], uint32_t bechash[])
{
	for (int i = 0; i < 8; i++) 
	{
		be32enc(bechash + i, bufhash[7 - i]);
	}
}

void printme(char *caption, uint32_t bufhash[])
{
	char sha_str[65];
	bin2hex(sha_str, (unsigned char *)bufhash, 32);
	printf("\n %s ---  HASH [%s]\n ", caption, sha_str);
}


#ifndef EXTERN_POBH2
int scanhash_pobh2(int thr_id, uint32_t *pdata, const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t hash[8] __attribute__((aligned(128)));
	uint32_t endiandata[20] __attribute__((aligned(128)));
	const uint32_t first_nonce = pdata[19];
	const uint32_t starttime = pdata[17] + thr_id;
	le32enc(&pdata[17], starttime);
	uint32_t nonce = first_nonce;
    bool fLate = false;
 	uint8_t pobhhash[32] = {0x0};
	uint8_t pobhhash2[32] = {0x0};
	uint32_t finalhash[8] __attribute__((aligned(32)));
	uint32_t hash_be[8]= {0x0};
	for (int k=0; k < 20; k++)
		endiandata[k] = pdata[k];

	do 
	{
    	be32enc(&endiandata[19], nonce);
		x11hash(hash, endiandata);
		becencode(hash, hash_be);
		ConvertH32TO8(hash_be, pobhhash);
		BibleHashV2(pobhhash, fLate);
	    R256b(pobhhash, pobhhash2);
		ConvertH8TO32(pobhhash2, finalhash);
		
		if (fulltest(finalhash, ptarget)) 
		{
			be32enc(&pdata[19], nonce);
			if (opt_debug)
			{
				printme2("\n SOLUTION FOUND !!!! \nx11", hash);
				printme2("bbphash\n", finalhash);
			}
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

#endif
