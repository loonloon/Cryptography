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

#ifdef ENCLAVEBRIDGE_API_EXPORTING
#    define ENCLAVEBRIDGE_API __declspec(dllexport)
#include <sgx_urts.h>
#else
#    define ENCLAVEBRIDGE_API __declspec(dllimport)
#include <Windows.h>
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

ENCLAVEBRIDGE_API int ew_initialize();
ENCLAVEBRIDGE_API int ew_initialize_from_header(const char *header, uint16_t hsize);

ENCLAVEBRIDGE_API int ew_unlock(const char *password);
ENCLAVEBRIDGE_API int ew_lock();

ENCLAVEBRIDGE_API int ew_ping();

ENCLAVEBRIDGE_API int ew_is_locked(int *locked);
ENCLAVEBRIDGE_API int ew_is_valid(int *valid);

ENCLAVEBRIDGE_API int ew_load_vault(const unsigned char *edata);

ENCLAVEBRIDGE_API int ew_get_header(unsigned char *header, uint16_t *size);

ENCLAVEBRIDGE_API int ew_get_vault(unsigned char *edata, uint32_t *size);

ENCLAVEBRIDGE_API int ew_set_master_password(const char *password);
ENCLAVEBRIDGE_API int ew_change_master_password(const char *oldpass, const char *newpass);

ENCLAVEBRIDGE_API int ew_accounts_get_count(uint32_t *count);
ENCLAVEBRIDGE_API int ew_accounts_get_info_sizes(uint32_t idx, uint16_t *mbname_sz, uint16_t *mblogin_sz, uint16_t *mburl_sz);
ENCLAVEBRIDGE_API int ew_accounts_get_info(uint32_t idx, char *mbname, uint16_t mbname_sz, char *mblogin, uint16_t mblogin_sz,
	char *mburl, uint16_t mburl_sz);

ENCLAVEBRIDGE_API int ew_accounts_get_password_size(uint32_t idx, uint16_t *len);
ENCLAVEBRIDGE_API int ew_accounts_get_password(uint32_t idx, char *mbpass, uint16_t len);

ENCLAVEBRIDGE_API int ew_accounts_set_info(uint32_t idx, const char *mbname, uint16_t mbname_len, const char *mblogin, uint16_t mblogin_len,
	const char *mburl, uint16_t mburl_len);
ENCLAVEBRIDGE_API int ew_accounts_set_password(uint32_t idx, const char *mbpass, uint16_t mbpass_len);

ENCLAVEBRIDGE_API int ew_accounts_generate_password(uint16_t length, uint16_t pwflags, char *buffer);

ENCLAVEBRIDGE_API int ew_get_state_size(uint32_t *sz);
ENCLAVEBRIDGE_API int ew_heartbeat(char *state, uint32_t sz);
ENCLAVEBRIDGE_API int ew_set_lock_delay(uint16_t secs);
ENCLAVEBRIDGE_API int ew_restore_state(char *state, uint32_t sz);

ENCLAVEBRIDGE_API const char *ew_sgx_error_string();

#ifdef __cplusplus
};
#endif