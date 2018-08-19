#pragma once

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

#include "common.h"
#include "dllexport.h"
#include <Windows.h>

class PASSWORDMANAGERCORE_API DRNG
{
	int rand32 (ULONG32 *rand);
	int rand64 (ULONG64 *rand);
	ULONG get_n_rand32 (ULONG32 *buf, ULONG n, ULONG retries);
	ULONG get_n_rand64 (ULONG64 *buf, ULONG n, ULONG retries);

	int seed32 (ULONG32 *seed);
	int seed64 (ULONG64 *seed);
	ULONG get_n_seed32 (ULONG32 *buf, ULONG n, ULONG retries);
	ULONG get_n_seed64 (ULONG64 *buf, ULONG n, ULONG retries);

	ULONG seed_from_rdrand (void *buf, ULONG n);

	int ceiling_log2 (ULONGLONG n);

public:
	DRNG(void);
	~DRNG(void);

	int have_rdrand(void);
	int have_rdseed(void);

	// General purpose random numbers 0 <= r < max

	int random (ULONGLONG max, ULONGLONG *rand);

	// Random seeds, suitable for static encryption keys and seeding
	// other PRNGs.

	ULONG get_seed_bytes (void *buf, ULONG n);
	ULONG get_rand_bytes (void *buf, ULONG n);
};

