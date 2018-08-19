/*
Copyright 2016, Intel Corporation.

The source code, information and material("Material") contained herein is
owned by Intel Corporation or its suppliers or licensors, and title to
such Material remains with Intel Corporation or its suppliers or licensors.
The Material contains proprietary information of Intel or its suppliers and
licensors. The Material is protected by worldwide copyright laws and treaty
provisions.No part of the Material may be used, copied, reproduced,
modified, published, uploaded, posted, transmitted, distributed or
disclosed in any way without Intel's prior express written permission. No
license under any patent, copyright or other intellectual property rights
in the Material is granted to or conferred upon you, either expressly, by
implication, inducement, estoppel or otherwise. Any license under such
intellectual property rights must be express and approved by Intel in
writing.

Unless otherwise agreed by Intel in writing, you may not remove or alter
this notice or any other notice embedded in Materials by Intel or Intel's
suppliers or licensors in any way.
*/

#include "E_DRNG.h"
#include <sgx.h>
#include <sgx_trts.h>
#include <sgx_cpuid.h>
#include <sgx_tcrypto.h>
#include <sgx_intrin.h>
#include <string.h>

#define DRNG_SUPPORT_UNKNOWN	-1
#define DRNG_SUPPORT_NONE		0
#define DRNG_SUPPORT_RDRAND		0x01
#define DRNG_SUPPORT_RDSEED		0x02

#define HAVE_RDRAND ((_drng_support & DRNG_SUPPORT_RDRAND)==DRNG_SUPPORT_RDRAND)
#define HAVE_RDSEED ((_drng_support & DRNG_SUPPORT_RDSEED)==DRNG_SUPPORT_RDSEED)

#ifdef __ICL
#define COMPILER_HAS_RDSEED_SUPPORT 1
#else
#	if _MSC_VER >= 1800
#	define COMPILER_HAS_RDSEED_SUPPORT 1
#	endif
#endif

static int _drng_support = DRNG_SUPPORT_UNKNOWN;

E_DRNG::E_DRNG(void)
{
	int info[4];

	if (_drng_support != DRNG_SUPPORT_UNKNOWN)
	{
		return;
	}

	_drng_support = DRNG_SUPPORT_NONE;

	// Check our feature support
	sgx_status_t status = sgx_cpuid(info, 0);

	if (status != SGX_SUCCESS)
	{
		return;
	}

	if (memcmp(&(info[1]), "Genu", 4) ||
		memcmp(&(info[3]), "ineI", 4) ||
		memcmp(&(info[2]), "ntel", 4))
	{
		return;
	}

	status = sgx_cpuidex(info, 1, 0);

	if (status != SGX_SUCCESS)
	{
		return;
	}

	if (info[2] & (1 << 30))
	{
		_drng_support |= DRNG_SUPPORT_RDRAND;
	}

#ifdef COMPILER_HAS_RDSEED_SUPPORT
	status = __cpuidex(info, 7, 0);

	if (status != SGX_SUCCESS)
	{
		return;
	}

	if (info[1] & (1 << 18))
	{
		_drng_support |= DRNG_SUPPORT_RDSEED;
	}
#endif
}

E_DRNG::~E_DRNG(void)
{
}

int E_DRNG::have_rdseed()
{
	return HAVE_RDSEED;
}

int E_DRNG::random(uint64_t max, uint64_t *rand)
{
	int retries = 1000; // A big enough number make failure extremely unlikely.

	if (max == 0) 
	{
		*rand = 0;
		return 1;
	}

	unsigned int bits = ceiling_log2(max);

	if (bits > 32) {
		uint64_t val;

		while (retries--) {
			if (!rand64(&val)) return 0;

			val >>= (64 - bits);

			if (val < max) {
				*rand = (uint64_t)val;
				return 1;
			}
		}
	}
	else {
		uint32_t val;

		while (retries--) {
			if (!rand32(&val)) return 0;

			val >>= (32 - bits);

			if (val < max) {
				*rand = (uint64_t)val;
				return 1;
			}
		}
	}

	// Keep the compiler from complaining.
	return 0;
}

unsigned long E_DRNG::get_rand_bytes(void *buf, unsigned long n)
{
	unsigned long count = 0;
	unsigned char rand[8];
	unsigned char * pb = (unsigned char *)buf;
#ifdef _WIN64
	unsigned long blocks = int(n / 8);

	if (!HAVE_RDRAND) return 0;

	count = get_n_rand64((uint64_t *)pb, blocks, 100 * blocks);
	if (count < blocks) return count * 8;
	else count *= 8;
	pb += blocks * 8;
#else
	unsigned long blocks = int(n / 4);

	count = get_n_rand32((uint32_t *)pb, blocks, 200 * blocks);
	if (count < blocks) return count * 4;
	else count *= 4;
	pb += blocks * 4;
#endif

	if (!rand64((uint64_t *)rand)) return count;
	memcpy(pb, rand, (n - count));

	return n;
}

unsigned long E_DRNG::get_seed_bytes(void *buf, unsigned long n)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	unsigned long count = 0;
	unsigned char seed[8];
	unsigned char *pb = (unsigned char *)buf;
	unsigned long blocks;

	if (!HAVE_RDSEED) return seed_from_rdrand(buf, n);

# ifdef _WIN64
	blocks = int(n / 8);
	count = get_n_seed64((uint64_t *)pb, blocks, 100 * blocks);
	if (count < blocks) return count * 8;
	else count *= 8;
	pb += blocks * 8;
# else
	blocks = int(n / 4);
	count = get_n_seed32((uint32_t *)pb, blocks, 200 * blocks);
	if (count < blocks) return count * 4;
	else count *= 4;
	pb += blocks * 4;
# endif

	if (!seed64((uint64_t *)seed)) return count;
	memcpy(pb, seed, (n - count));

	return n;
#else
	return seed_from_rdrand(buf, n);
#endif
}

//-----------------------------------------------
// RDRAND internal methods
//-----------------------------------------------

int E_DRNG::rand32(uint32_t *rand)
{
	int retries = 10;

	if (!HAVE_RDRAND) return 0;

	while (retries--) if (_rdrand32_step(rand)) return 1;

	return 0;
}

int E_DRNG::rand64(uint64_t *rand)
{
	int retries = 10;

	if (!HAVE_RDRAND) return 0;

#ifdef _WIN64
	while (retries--) if (_rdrand64_step(rand)) return 1;
#else
	if (get_n_rand32((uint32_t *)rand, 2, 20) == 2) return 1;
#endif

	return 0;
}

unsigned long E_DRNG::get_n_rand32(uint32_t *buf, unsigned long n, unsigned long retries)
{
	unsigned long count = 0;

	if (!HAVE_RDRAND) return 0;

	while (n) {
		if (_rdrand32_step(buf)) {
			--n;
			++buf;
			++count;
		}
		else {
			if (!retries) return count;
			retries--;
		}
	}

	return count;
}

unsigned long E_DRNG::get_n_rand64(uint64_t *buf, unsigned long n, unsigned long retries)
{
	unsigned long count = 0;

	if (!HAVE_RDRAND) return 0;
#ifdef _WIN64

	while (n) {
		if (_rdrand64_step(buf)) {
			--n;
			++buf;
			++count;
		}
		else {
			if (!retries) return count;
			retries--;
		}
	}

	return count;
#else
	count = get_n_rand32((uint32_t *)buf, n, retries);
	if (count == n) {
		count = get_n_rand32((uint32_t *)(buf)+count, n, retries);
		if (count == n) return n;
		return n / 2 + int(count / 2);
	}

	return int(count / 2);
#endif
}


//-----------------------------------------------
// RDSEED internal methods
//-----------------------------------------------

int E_DRNG::seed32(uint32_t *seed)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	int retries = 100;

	if (!HAVE_RDSEED) return seed_from_rdrand(seed, 4);

	while (retries--) {
		if (_rdseed32_step(seed)) return 1;
		_mm_pause();
	}

	return 0;
#else
	return seed_from_rdrand(seed, 4);
#endif
}

int E_DRNG::seed64(uint64_t *seed)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	int retries = 100;

	if (!HAVE_RDSEED) return seed_from_rdrand(seed, 8);

# ifdef _WIN64
	while (retries--) {
		if (_rdseed64_step(seed)) return 1;
		_mm_pause();
	}
# else
	if (get_n_seed32((uint32_t *)seed, 2, 2 * retries) == 2) return 1;
# endif

	return 0;
#else
	return seed_from_rdrand(seed, 8);
#endif
}

unsigned long E_DRNG::get_n_seed32(uint32_t *buf, unsigned long n, unsigned long retries)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	unsigned long count = 0;

	if (!HAVE_RDSEED) return seed_from_rdrand(buf, 4 * n);

	while (n) {
		if (_rdseed32_step(buf)) {
			--n;
			++buf;
			++count;
		}
		else {
			if (!retries) return count;
			retries--;
		}
		_mm_pause();
	}

	return count;
#else
	return seed_from_rdrand(buf, 4 * n);
#endif
}

unsigned long E_DRNG::get_n_seed64(uint64_t *buf, unsigned long n, unsigned long retries)
{
#ifdef COMPILER_HAS_RDSEED_SUPPORT
	unsigned long count = 0;

	if (!HAVE_RDSEED) return seed_from_rdrand(buf, 8 * n);

# ifdef _WIN64
	while (n) {
		if (_rdseed64_step(buf)) {
			--n;
			++buf;
			++count;
		}
		else {
			if (!retries) return count;
			retries--;
		}
		_mm_pause();
	}

	return count;
# else
	count = get_n_seed32((uint32_t *)buf, n, retries);
	if (count == n) {
		count = get_n_seed32((uint32_t *)(buf)+count, n, retries);
		if (count == n) return n;
		return n / 2 + int(count / 2);
	}

	return int(count / 2);
# endif
#else
	return seed_from_rdrand(buf, 8 * n);
#endif
}

unsigned long E_DRNG::seed_from_rdrand(void *buf, unsigned long n)
{
	// Use CMAC to generate 128-bit seeds from RDRAND. This is expensive
	// but if we don't have RDSEED this is our only option.
	//
	// The DRNG is guaranteed to reseed after 512 128-bit samples have been generated.

	unsigned char key[16], rand[16 * 512];
	sgx_cmac_128bit_tag_t hash;
	unsigned char *bp = (unsigned char *)buf;
	unsigned long count = 0;
	sgx_cmac_state_handle_t hcmac;

	// Create an ephemeral key

	if (get_n_rand64((uint64_t *)key, 2, 20) != 2) return 0;

	// Set up CMAC

	if (sgx_cmac128_init((const sgx_cmac_128bit_key_t *)key, &hcmac) != SGX_SUCCESS) {
		return 0;
	}

	while (n) {
		unsigned long chunk = (n >= 16) ? 16 : n;

		// Fill our buffer with RDRAND values

		if (get_n_rand64((uint64_t *)rand, 1024, 10240) != 1024) {
			goto cleanup;
		}

		// Send our random values

		if (sgx_cmac128_update(rand, 16 * 512, hcmac) != SGX_SUCCESS) {
			// Error
			goto cleanup;
		}

		// The hash is our 128-bit seed value

		if (sgx_cmac128_final(hcmac, &hash) != SGX_SUCCESS) {
			// Error
			goto cleanup;
		}

		memcpy(bp, hash, chunk);
		count += chunk;
		n -= chunk;
		bp += chunk;
	}

cleanup:
	sgx_cmac128_close(hcmac);
	return count;
}

// Fast ceiling of log base 2
// http://stackoverflow.com/questions/3272424/compute-fast-log-base-2-ceiling
// Question asked by: kevinlawler (http://stackoverflow.com/users/365478/kevinlawler)
// Answered by: dgobbi (http://stackoverflow.com/users/2154690/dgobbi)
// Licensed under http://creativecommons.org/licenses/by-sa/3.0/
// Changes to variable names only. [-JM]

int E_DRNG::ceiling_log2(uint64_t n)
{
	static const uint64_t t[] = {
		0xFFFFFFFF00000000ull,
		0x00000000FFFF0000ull,
		0x000000000000FF00ull,
		0x00000000000000F0ull,
		0x000000000000000Cull,
		0x0000000000000002ull
	};
	int i, j, k, m;

	j = 32;
	m = (((n&(n - 1)) == 0) ? 0 : 1);

	for (i = 0; i < 6; ++i) {
		k = (((n&t[i]) == 0) ? 0 : j);
		m += k;
		n >>= k;
		j >>= 1;
	}

	return m;
}