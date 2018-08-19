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

#define NL_STATUS_OK				0x0000L
#define NL_STATUS_NO_CHANGE			0x0001L
#define NL_STATUS_ALLOC				0x0002L
#define NL_STATUS_SIZE				0x0003L
#define NL_STATUS_RANGE				0x0004L
#define NL_STATUS_EXISTS			0x0005L
#define NL_STATUS_PERM				0x0006L
#define NL_STATUS_NOTFOUND			0x0007L
#define NL_STATUS_INVALID			0x0008L
#define NL_STATUS_VERSION			0x0009L
#define NL_STATUS_BADFILE			0x000AL
#define NL_STATUS_RAND				0x000BL
#define NL_STATUS_USER_CANCEL		0x000CL
#define NL_STATUS_PASSWORD			0x000DL
#define NL_STATUS_CLIPBOARD			0x000EL
#define NL_STATUS_UPDATE			0x000FL
#define NL_STATUS_WRITE				0x0010L
#define NL_STATUS_AGAIN				0x0011L
#define NL_STATUS_MISMATCH			0x0012L

#define NL_STATUS_SGXERROR			0x1000L
#define NL_STATUS_LOST_ENCLAVE		0x1001L
#define NL_STATUS_RECREATED_ENCLAVE	0x1002L

#define NL_STATUS_UNKNOWN			0x7FFFFFFFL