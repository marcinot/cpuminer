#include "cuda_helper.h"
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef uint8_t u8;


#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4
#define MD5_H0	0x67452301UL
#define MD5_H1	0xefcdab89UL
#define MD5_H2	0x98badcfeUL
#define MD5_H3	0x10325476UL


struct md5_state {
	u32 hash[MD5_HASH_WORDS];
	u32 block[MD5_BLOCK_WORDS];
	u64 byte_count;
};




#define MD5_DIGEST_WORDS 4
#define MD5_MESSAGE_BYTES 64


#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#define F2(x, y, z)	F1(z, x, y)
#define F3(x, y, z)	(x ^ y ^ z)
#define F4(x, y, z)	(y ^ (x | ~z))
#define MD5STEP(f, w, x, y, z, in, s) \
	(w += f(x, y, z) + in, w = (w<<s | w>>(32-s)) + x)
__device__ void md5_transform(u32 *hash, u32 const *in)
{
	u32 a, b, c, d;
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);
	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);
	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);
	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}
__device__ inline void md5_transform_helper(struct md5_state *ctx)
{
	
	md5_transform(ctx->hash, ctx->block);
}

__device__ int md5_init(struct md5_state *mctx)
{
	mctx->hash[0] = MD5_H0;
	mctx->hash[1] = MD5_H1;
	mctx->hash[2] = MD5_H2;
	mctx->hash[3] = MD5_H3;
	mctx->byte_count = 0;
	return 0;
}

__device__ void my_memcpy_2(void* dest, const void* src, uint32_t size, const void* src_base)
{
	uint8_t* src_8 = (uint8_t*) src;
	uint8_t* src_base_8 = (uint8_t*) src_base;	
	uint8_t* dest_8 = (uint8_t*) dest;

	uint32_t r = (src_8 - src_base_8) & 0x7;
	uint64_t* src_64_bs = (uint64_t*)(src_8 - r);

	uint64_t current64 = (*src_64_bs >> r*8);
	
	for(uint32_t i=0; i<size; i++)
	{				
		*dest_8++ = current64 & 0xff;
		
		current64>>=8;
		r = (r+1) & 0x7;
		
		if (!r)
		{			
			current64 = *++src_64_bs;
		}
	}

}



__device__ int md5_update(struct md5_state *mctx, const u8 *data, unsigned int len)
{
	const u8* data_org = data;

	const u32 avail = sizeof(mctx->block) - (mctx->byte_count & 0x3f);
	mctx->byte_count += len;
	if (avail > len) {
		/*memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
		       data, len);*/

		my_memcpy_2((char *)mctx->block + (sizeof(mctx->block) - avail),
		       data, len, data_org);	   
		return 0;
	}
	/*memcpy((char *)mctx->block + (sizeof(mctx->block) - avail),
	       data, avail);*/

	my_memcpy_2((char *)mctx->block + (sizeof(mctx->block) - avail),
	       data, avail, data_org);		   

	md5_transform_helper(mctx);
	data += avail;
	len -= avail;
	while (len >= sizeof(mctx->block)) {
		//memcpy(mctx->block, data, sizeof(mctx->block));
		my_memcpy_2(mctx->block, data, sizeof(mctx->block), data_org);
		
		

		md5_transform_helper(mctx);
		data += sizeof(mctx->block);
		len -= sizeof(mctx->block);
	}

	//memcpy(mctx->block, data, len);
	my_memcpy_2(mctx->block, data, len, data_org);
	return 0;
}

__device__ int md5_final(struct md5_state *mctx, u8 *out)
{
	const unsigned int offset = mctx->byte_count & 0x3f;
	char *p = (char *)mctx->block + offset;
	int padding = 56 - (offset + 1);
	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + sizeof (u64));
		md5_transform_helper(mctx);
		p = (char *)mctx->block;
		padding = 56;
	}
	memset(p, 0, padding);
	mctx->block[14] = mctx->byte_count << 3;
	mctx->block[15] = mctx->byte_count >> 29;

	md5_transform(mctx->hash, mctx->block);
	memcpy(out, mctx->hash, sizeof(mctx->hash));
	memset(mctx, 0, sizeof(*mctx));
	return 0;
}

__device__ void gpu_EncodeBase64(const unsigned char* pch, size_t len, char* strRet, int* outlen)
{
    static const char *pbase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int k = 0;

    int mode=0, left=0;
    const unsigned char *pchEnd = pch+len;

    while (pch<pchEnd)
    {
        int enc = *(pch++);
        switch (mode)
        {
            case 0: // we have no bits
                strRet[k++] = pbase64[enc >> 2];
                left = (enc & 3) << 4;
                mode = 1;
                break;

            case 1: // we have two bits
                strRet[k++] = pbase64[left | (enc >> 4)];
                left = (enc & 15) << 2;
                mode = 2;
                break;

            case 2: // we have four bits
                strRet[k++] = pbase64[left | (enc >> 6)];
                strRet[k++] = pbase64[enc & 63];
                mode = 0;
                break;
        }
    }

    if (mode)
    {
        strRet[k++] = pbase64[left];
        strRet[k++] = '=';
        if (mode == 1)
            strRet[k++] = '=';
    }

    strRet[k] = 0;
	*outlen = k;
}

#define INT_TO_CHAR(x) ((x)<10 ? ('0'+(x)) : ('a'+(x)-10))

__device__ void gpu_hash_to_str(unsigned char* digest2, char* mdString2)
{ 
	for(int i = 0; i < 16; i++) 
	{
		uint8_t mh = digest2[i] & 0xf;
		uint8_t sh = (digest2[i]>>4) & 0xf;
		mdString2[i*2+1] = INT_TO_CHAR(mh);
		mdString2[i*2] = INT_TO_CHAR(sh);
	}
	mdString2[32]=0;
}


__global__ void gpu_md5_all(int threads, uint8_t* hashes)
{
	const uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads)
	{
        uint8_t* inp = hashes + thread * 64;

		char buf[96];
		int buflen = 0;

		gpu_EncodeBase64(inp, 48, buf, &buflen);


		
		uint8_t dig[16];

        md5_state ctx;
        md5_init(&ctx);
        md5_update(&ctx, (u8*)buf, buflen);
        md5_final(&ctx, dig);
        


		gpu_hash_to_str(dig, (char*)inp);

	

	}
}

__host__ void cpu_md5_all(uint32_t num_hashes, uint8_t* hashes)
{
	int threads = num_hashes;	
	const uint32_t threadsperblock = 256;
	dim3 grid((threads + threadsperblock-1)/threadsperblock);
	dim3 block(threadsperblock);
	gpu_md5_all <<<grid, block >>> (threads, hashes);	
	CUDA_SAFE_CALL(cudaGetLastError());	
}


/* kjv + md5 */



__device__ int md5_ATD(int iAscii)
{
	int iOut=(0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00);
	switch (iAscii)
	{
		case (0x0000000000000060 + 0x0000000000000230 + 0x0000000000000830 - 0x0000000000000A90):
			iOut = (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00);
			break;
		case (0x0000000000000062 + 0x0000000000000231 + 0x0000000000000831 - 0x0000000000000A93):
			iOut = (0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03);
			break;
		case (0x0000000000000064 + 0x0000000000000232 + 0x0000000000000832 - 0x0000000000000A96):
			iOut = (0x0000000000000004 + 0x0000000000000202 + 0x0000000000000802 - 0x0000000000000A06);
			break;
		case (0x0000000000000066 + 0x0000000000000233 + 0x0000000000000833 - 0x0000000000000A99):
			iOut = (0x0000000000000006 + 0x0000000000000203 + 0x0000000000000803 - 0x0000000000000A09);
			break;
		case (0x0000000000000068 + 0x0000000000000234 + 0x0000000000000834 - 0x0000000000000A9C):
			iOut = (0x0000000000000008 + 0x0000000000000204 + 0x0000000000000804 - 0x0000000000000A0C);
			break;
		case (0x000000000000006A + 0x0000000000000235 + 0x0000000000000835 - 0x0000000000000A9F):
			iOut = (0x000000000000000A + 0x0000000000000205 + 0x0000000000000805 - 0x0000000000000A0F);
			break;
		case (0x000000000000006C + 0x0000000000000236 + 0x0000000000000836 - 0x0000000000000AA2):
			iOut = (0x000000000000000C + 0x0000000000000206 + 0x0000000000000806 - 0x0000000000000A12);
			break;
		case (0x000000000000006E + 0x0000000000000237 + 0x0000000000000837 - 0x0000000000000AA5):
			iOut = (0x000000000000000E + 0x0000000000000207 + 0x0000000000000807 - 0x0000000000000A15);
			break;
		case (0x0000000000000070 + 0x0000000000000238 + 0x0000000000000838 - 0x0000000000000AA8):
			iOut = (0x0000000000000010 + 0x0000000000000208 + 0x0000000000000808 - 0x0000000000000A18);
			break;
		case (0x0000000000000072 + 0x0000000000000239 + 0x0000000000000839 - 0x0000000000000AAB):
			iOut = (0x0000000000000012 + 0x0000000000000209 + 0x0000000000000809 - 0x0000000000000A1B);
			break;
		case (0x00000000000000C2 + 0x0000000000000261 + 0x0000000000000861 - 0x0000000000000B23):
			iOut = (0x0000000000000014 + 0x000000000000020A + 0x000000000000080A - 0x0000000000000A1E);
			break;
		case (0x00000000000000C4 + 0x0000000000000262 + 0x0000000000000862 - 0x0000000000000B26):
			iOut = (0x0000000000000016 + 0x000000000000020B + 0x000000000000080B - 0x0000000000000A21);
			break;
		case (0x00000000000000C6 + 0x0000000000000263 + 0x0000000000000863 - 0x0000000000000B29):
			iOut = (0x0000000000000018 + 0x000000000000020C + 0x000000000000080C - 0x0000000000000A24);
			break;
		case (0x00000000000000C8 + 0x0000000000000264 + 0x0000000000000864 - 0x0000000000000B2C):
			iOut = (0x000000000000001A + 0x000000000000020D + 0x000000000000080D - 0x0000000000000A27);
			break;
		case (0x00000000000000CA + 0x0000000000000265 + 0x0000000000000865 - 0x0000000000000B2F):
			iOut = (0x000000000000001C + 0x000000000000020E + 0x000000000000080E - 0x0000000000000A2A);
			break;
		case (0x00000000000000CC + 0x0000000000000266 + 0x0000000000000866 - 0x0000000000000B32):
			iOut = (0x000000000000001E + 0x000000000000020F + 0x000000000000080F - 0x0000000000000A2D);
			break;
	};
	return iOut;
};

__device__ int md5_HTD(const unsigned char* sOctet)
{
	int i1=md5_ATD((int)sOctet[0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00]);
	int i2=md5_ATD((int)sOctet[0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03]);
	int i3=md5_ATD((int)sOctet[0x0000000000000004 + 0x0000000000000202 + 0x0000000000000802 - 0x0000000000000A06]);
	int i4=md5_ATD((int)sOctet[0x0000000000000006 + 0x0000000000000203 + 0x0000000000000803 - 0x0000000000000A09]);
	int iOut=(i1 * (0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30) * 
		(0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30) * 
		(0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30)) + 
		(i2 * (0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30) * 
		(0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30)) + 
		(i3 * (0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30)) + (i4);
	return iOut;
};

__device__ void md5_my_memcpy(void* dest, const void* src, uint32_t size)
{    
    uint64_t* src_64 = (uint64_t*)(src);
    uint64_t* dest_64 = (uint64_t*)dest;
	
    uint32_t n = (size / 8);
	uint32_t r = size - n*8;

	if (r>0)
		n++;

    for(uint32_t i=0; i< n ; i++)
    {
		dest_64[i] = src_64[i];
    }


}


//POPRAWIC !!! MD5 + aligned + 64bit copy
__device__ void GVFromHash(char* kjv, uint16_t* kjv_len, const unsigned char* sHash, md5_state& ctx) { 
	double iVerseFactor = .4745708; //Verses available divided by bits per octet

	//uint64_t buff[544/8];


	int len = 0;
    for (int i = 0; i < 32; i = i + 4) 
    { 
		int iVerse = md5_HTD(sHash + i) * iVerseFactor; 		 
		const char* b_src_org = kjv + iVerse * 544;
		len = kjv_len[iVerse];
		//md5_my_memcpy(buff,  b_src_org, len);				
		md5_update(&ctx, (u8*)b_src_org, len);
	} 	
	
}


__global__ void gpu_kjv_md5_all(int threads, uint8_t* hashes, char* kjv, uint16_t* kjv_len)
{
	const uint32_t thread = (blockDim.x * blockIdx.x + threadIdx.x);
	if (thread < threads)
	{
        uint8_t* inp = hashes + thread * 64;
        //__shared__ md5_state ctxes[256];
		

		//md5_state& ctx = ctxes[threadIdx.x];

		md5_state ctx;

		
        md5_init(&ctx);

		GVFromHash(kjv, kjv_len, inp, ctx);

		uint8_t dig[16];
        //MD5_Update(&ctx, buff, buff_len);
        md5_final(&ctx, dig);
        
		gpu_hash_to_str(dig, (char*)inp);		
	}
}

__host__ void cpu_kjv_md5_all(uint32_t num_hashes, uint8_t* hashes, char* kjv, uint16_t* kjv_len)
{
	int threads = num_hashes;	
	const uint32_t threadsperblock = 256;
	dim3 grid((threads + threadsperblock-1)/threadsperblock);
	dim3 block(threadsperblock);
	gpu_kjv_md5_all <<<grid, block >>> (threads, hashes, kjv, kjv_len);	
	CUDA_SAFE_CALL(cudaGetLastError());	
}



