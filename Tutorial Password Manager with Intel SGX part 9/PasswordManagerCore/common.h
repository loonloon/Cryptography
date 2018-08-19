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

#pragma warning(disable: 4793) // Suppress "function compiled as native" warnings

#include "PasswordManagerError.h"

#define NL_PWFLAG_LOWER		0x1
#define NL_PWFLAG_UPPER		0x2
#define NL_PWFLAG_NUMERIC	0x4
#define NL_PWFLAG_SPECIAL	0x8
#define NL_PWFLAG_ALL		NL_PWFLAG_SPECIAL|NL_PWFLAG_NUMERIC|NL_PWFLAG_UPPER|NL_PWFLAG_LOWER

#define	CLIPBOARD_CLEAR_SECS	15
