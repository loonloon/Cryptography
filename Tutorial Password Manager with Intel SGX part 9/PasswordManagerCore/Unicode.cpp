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
#include "Unicode.h"
#include <Windows.h>

namespace Unicode
{
	// This looks bad because we take a string that is 32-bits in size and convert it
	// to a string that can be at most 16-bits in size. But, our multibyte strings
	// can be at most 16-bits, and w_char can potentially double the size. So, it
	// has to be 32-bit.
	//
	// Not that this matters. Who has a 65k character password, etc?

	char *tombs(const wchar_t *in, UINT32 wlen, UINT16 *len)
	{
		char *buffer;
		*len = (UINT16)WideCharToMultiByte(CP_UTF8, 0, in, wlen, NULL, 0, NULL, NULL);
		buffer = new char[*len];

		if (buffer == NULL)
		{
			return NULL;
		}

		WideCharToMultiByte(CP_UTF8, 0, in, wlen, buffer, *len, NULL, NULL);
		return buffer;
	}

	wchar_t *towchar(const char *in, UINT32 len, UINT16 *wlen)
	{
		wchar_t *buffer;
		*wlen = (UINT16)MultiByteToWideChar(CP_UTF8, 0, in, len, NULL, 0); // Make sure we never allocate a 0-size buffer if we are passed a 0-length string.
		buffer = new wchar_t[*wlen];

		if (buffer == NULL)
		{
			return NULL;
		}

		MultiByteToWideChar(CP_UTF8, 0, in, len, buffer, *wlen);
		return buffer;
	}
};