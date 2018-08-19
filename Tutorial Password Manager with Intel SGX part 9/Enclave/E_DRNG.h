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

#pragma once

#include <sgx.h>

class E_DRNG;
typedef class E_DRNG E_DRNG;

class E_DRNG
{
	int rand32 (uint32_t *rand);
	int rand64 (uint64_t *rand);
	unsigned long get_n_rand32 (uint32_t *buf, unsigned long n, unsigned long retries);
	unsigned long get_n_rand64 (uint64_t *buf, unsigned long n, unsigned long retries);

	int seed32 (uint32_t *seed);
	int seed64 (uint64_t *seed);
	unsigned long get_n_seed32 (uint32_t *buf, unsigned long n, unsigned long retries);
	unsigned long get_n_seed64 (uint64_t *buf, unsigned long n, unsigned long retries);

	unsigned long seed_from_rdrand (void *buf, unsigned long n);

	int ceiling_log2 (unsigned long long n);

public:
	E_DRNG(void);
	E_DRNG(int *info);
	~E_DRNG(void);

	int have_rdseed(void);

	// General purpose random numbers 0 <= r < max

	int random (unsigned long long max, unsigned long long *rand);

	// Random seeds, suitable for static encryption keys and seeding
	// other PRNGs.

	unsigned long get_seed_bytes (void *buf, unsigned long n);
	unsigned long get_rand_bytes (void *buf, unsigned long n);
};

