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

#include "stdafx.h"
#include "Pack.h"
#include <Windows.h>

namespace Pack
{
	UINT16 unpack_uint16(const PBYTE cp)
	{
		return (UINT32)cp[0] + ((UINT32)cp[1] << 8);
	}

	UINT32 unpack_uint32(const PBYTE cp)
	{
		return (UINT32)cp[0] + ((UINT32)cp[1] << 8) + ((UINT32)cp[2] << 16) + ((UINT32)cp[3] << 24);
	}

	void pack_uint16(PBYTE cp, UINT16 v)
	{
		cp[0] = (BYTE)(v & 0x00FF);
		cp[1] = (BYTE)((v & 0xFF00) >> 8);
	}

	void pack_uint32(PBYTE cp, UINT32 v)
	{
		cp[0] = (BYTE)(v & 0x000000FF);
		cp[1] = (BYTE)((v & 0x0000FF00) >> 8);
		cp[2] = (BYTE)((v & 0x00FF0000) >> 16);
		cp[3] = (BYTE)((v & 0xFF000000) >> 24);
	}
}
