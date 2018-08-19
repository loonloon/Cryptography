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

#define ENCLAVEBRIDGE_API_EXPORTING 1

#include "EnclaveBridge.h"
#include "sgx_urts.h"
#include <stdio.h>
#include <iostream>
#include <tchar.h>
#include <time.h>
#include "sgx_uae_service.h"
#include "PasswordManagerError.h"
#include "Enclave_u.h"

#define ENCLAVE_FILE _T("Enclave.signed.dll")
//#define MAX_BUF_LEN 100

static int get_enclave(sgx_enclave_id_t *eid);
static int create_enclave(sgx_enclave_id_t *eid);
static int lost_enclave();
static int recreate_enclave();

static sgx_enclave_id_t enclaveId = 0;
static sgx_launch_token_t launch_token = { 0 };
static int updated = 0;
static int launched = 0;
static sgx_status_t sgx_status = SGX_SUCCESS;

#define RETURN_SGXERROR_OR(X) if(sgx_status == SGX_SUCCESS) return X; else if (lost_enclave()) return recreate_enclave(); else return NL_STATUS_SGXERROR;

// Ensure the enclave has been created/launched.
static int get_enclave(sgx_enclave_id_t *eid)
{
	int rv;

	if (launched && enclaveId)
	{
		rv = 1;
	}
	else
	{
		rv = create_enclave(eid);
	}

	return rv;
}

static int create_enclave(sgx_enclave_id_t *eid)
{
	sgx_status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &launch_token, &updated, &enclaveId, NULL);

	if (sgx_status == SGX_SUCCESS)
	{
		if (eid != NULL)
		{
			*eid = enclaveId;
		}

		launched = 1;
		return 1;
	}

	return 0;
}

static int destroy_enclave()
{
	sgx_status = sgx_destroy_enclave(enclaveId);

	if (sgx_status == SGX_SUCCESS)
	{
		launched = 0;
		enclaveId = 0;
		return 1;
	}

	return 0;
}

// If we lose the enclave, we lose our data. Technically we should be able to recover from this.
static int lost_enclave()
{
	if (sgx_status == SGX_ERROR_ENCLAVE_LOST || sgx_status == SGX_ERROR_ENCLAVE_CRASHED)
	{
		return 1;
	}

	return 0;
}

static int recreate_enclave()
{
	if (destroy_enclave() == 0)
	{
		return NL_STATUS_LOST_ENCLAVE;
	}

	if (get_enclave(NULL))
	{
		return NL_STATUS_RECREATED_ENCLAVE;
	}

	return NL_STATUS_LOST_ENCLAVE;
}

ENCLAVEBRIDGE_API int ew_initialize()
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_initialize(enclaveId, &vault_rv);

	// If our enclave crashed try loading it again. We can recover from this here.
	if (lost_enclave())
	{
		if (recreate_enclave() == NL_STATUS_LOST_ENCLAVE)
		{
			return NL_STATUS_LOST_ENCLAVE;
		}

		sgx_status = ve_initialize(enclaveId, &vault_rv);
	}

	RETURN_SGXERROR_OR(vault_rv);
}

//read an existing vault
ENCLAVEBRIDGE_API int ew_initialize_from_header(const char *header, uint16_t hsize)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_initialize_from_header(enclaveId, &vault_rv, (unsigned char *)header, hsize);

	// If our enclave crashed try loading it again. We can recover from this here.

	if (lost_enclave())
	{
		if (recreate_enclave() == NL_STATUS_LOST_ENCLAVE)
		{
			return NL_STATUS_LOST_ENCLAVE;
		}

		sgx_status = ve_initialize_from_header(enclaveId, &vault_rv, (unsigned char *)header, hsize);
	}

	RETURN_SGXERROR_OR(vault_rv);
}


ENCLAVEBRIDGE_API int ew_unlock(const char *password)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_unlock(enclaveId, &vault_rv, (char *)password);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_lock()
{
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_lock(enclaveId);
	RETURN_SGXERROR_OR(NL_STATUS_OK);
}

ENCLAVEBRIDGE_API int ew_is_valid(int *valid)
{
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_is_valid(enclaveId, valid);
	RETURN_SGXERROR_OR(NL_STATUS_OK);
}

ENCLAVEBRIDGE_API int ew_is_locked(int *locked)
{
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_is_locked(enclaveId, locked);
	RETURN_SGXERROR_OR(NL_STATUS_OK);
}

ENCLAVEBRIDGE_API int ew_ping()
{
	int dummy;

	// We don't need a new API call for this, just re-use
	// an existing one and ignore what it says.
	//
	// All we care about is the return value of the
	// ECALL itself, which in turns tells us if the
	// enclave is alive, or if it crashed. If it
	// crashed, don't do anything about it, just
	// report that it crashed.
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_is_valid(enclaveId, &dummy);

	switch (sgx_status)
	{
	case SGX_SUCCESS:
		return NL_STATUS_OK;
	case SGX_ERROR_ENCLAVE_CRASHED:
	case SGX_ERROR_ENCLAVE_LOST:
		return NL_STATUS_LOST_ENCLAVE;
	default:
		return NL_STATUS_SGXERROR;
	}
}

ENCLAVEBRIDGE_API int ew_load_vault(const unsigned char *edata)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	// Send the pointer to our encrypted vault into the enclave, but
	// don't copy the data itself.
	sgx_status = ve_load_vault(enclaveId, &vault_rv, (unsigned char *)edata);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_get_header(unsigned char *header, uint16_t *size)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	if (header == NULL)
	{
		sgx_status = ve_get_header_size(enclaveId, &vault_rv, size);
	}
	else
	{
		sgx_status = ve_get_header(enclaveId, &vault_rv, header, *size);
	}

	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_get_vault(unsigned char *edata, uint32_t *size)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	if (edata == NULL) 
	{
		sgx_status = ve_get_db_size(enclaveId, size);
		RETURN_SGXERROR_OR(NL_STATUS_OK);
	}

	sgx_status = ve_get_vault(enclaveId, &vault_rv, edata, *size);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_set_master_password(const char *password)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_set_master_password(enclaveId, &vault_rv, (char *)password);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_change_master_password(const char *oldpass, const char *newpass)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_change_master_password(enclaveId, &vault_rv, (char *)oldpass, (char *)newpass);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_get_count(uint32_t *count)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_get_count(enclaveId, &vault_rv, count);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_get_info_sizes(uint32_t idx, uint16_t *mbname_sz, uint16_t *mblogin_sz, uint16_t *mburl_sz)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_get_info_sizes(enclaveId, &vault_rv, idx, mbname_sz, mblogin_sz, mburl_sz);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_get_info(uint32_t idx, char *mbname, uint16_t mbname_sz, char *mblogin, uint16_t mblogin_sz,
	char *mburl, uint16_t mburl_sz)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_get_info(enclaveId, &vault_rv, idx, mbname, mbname_sz, mblogin, mblogin_sz, mburl, mburl_sz);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_get_password_size(uint32_t idx, uint16_t *sz)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_get_password_size(enclaveId, &vault_rv, idx, sz);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_get_password(uint32_t idx, char *mbpass, uint16_t sz)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_get_password(enclaveId, &vault_rv, idx, mbpass, sz);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_set_info(uint32_t idx, const char *mbname, uint16_t mbname_len, const char *mblogin, uint16_t mblogin_len,
	const char *mburl, uint16_t mburl_len)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_set_info(enclaveId, &vault_rv, idx, (char *)mbname, mbname_len, (char *)mblogin, mblogin_len, (char *)mburl, mburl_len);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_set_password(uint32_t idx, const char *mbpass, uint16_t mbpass_len)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_set_password(enclaveId, &vault_rv, idx, (char *)mbpass, mbpass_len);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_accounts_generate_password(uint16_t length, uint16_t pwflags, char *buffer)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_accounts_generate_password(enclaveId, &vault_rv, length, pwflags, buffer);
	RETURN_SGXERROR_OR(vault_rv);
}

ENCLAVEBRIDGE_API int ew_get_state_size(uint32_t *sz)
{
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_get_state_size(enclaveId, sz);
	RETURN_SGXERROR_OR(NL_STATUS_OK);
}

ENCLAVEBRIDGE_API int ew_heartbeat(char *state, uint32_t sz)
{
	int vault_rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_heartbeat(enclaveId, &vault_rv, state, sz);

	// Don't try to recover the enclave from within the hearbeat.
	switch (sgx_status) 
	{
	case SGX_SUCCESS:
		return NL_STATUS_OK;
	case SGX_ERROR_ENCLAVE_LOST:
	case SGX_ERROR_ENCLAVE_CRASHED:
		return NL_STATUS_LOST_ENCLAVE;
	default:
		return NL_STATUS_SGXERROR;
	}
}

ENCLAVEBRIDGE_API int ew_set_lock_delay(uint16_t secs)
{
	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_set_lock_delay(enclaveId, secs);
	RETURN_SGXERROR_OR(NL_STATUS_OK);
}

ENCLAVEBRIDGE_API int ew_restore_state(char *state, uint32_t sz)
{
	int rv;

	if (!get_enclave(NULL))
	{
		return NL_STATUS_SGXERROR;
	}

	sgx_status = ve_restore_state(enclaveId, &rv, state, sz);

	if (sgx_status != SGX_SUCCESS)
	{
		return NL_STATUS_SGXERROR;
	}

	return rv;
}

ENCLAVEBRIDGE_API const char *ew_sgx_error_string()
{
	const char *msg;

	switch (sgx_status) 
	{
	case SGX_SUCCESS:
		msg = "No error";
		break;
	case SGX_ERROR_ENCLAVE_LOST:
		msg = "Enclave lost";
		break;
	case SGX_ERROR_ENCLAVE_CRASHED:
		msg = "Enclave crashed";
		break;
	case SGX_ERROR_INVALID_PARAMETER:
		msg = "Invalid parameter";
		break;
	case SGX_ERROR_SERVICE_UNAVAILABLE:
		msg = "Service unavailable";
		break;
	case SGX_ERROR_INVALID_ENCLAVE:
		msg = "Invalid enclave";
		break;
	case SGX_ERROR_OUT_OF_MEMORY:
		msg = "Out of memory";
		break;
	case SGX_ERROR_ENCLAVE_FILE_ACCESS:
		msg = "Enclave file access denied";
		break;
	case SGX_ERROR_INVALID_METADATA:
		msg = "Invalid enclave metadata";
		break;
	case SGX_ERROR_INVALID_VERSION:
		msg = "Invalid enclave version";
		break;
	case SGX_ERROR_INVALID_SIGNATURE:
		msg = "Invalid signature";
		break;
	case SGX_ERROR_OUT_OF_EPC:
		msg = "Out of protected memory";
		break;
	case SGX_ERROR_NO_DEVICE:
		msg = "No device";
		break;
	case SGX_ERROR_MEMORY_MAP_CONFLICT:
		msg = "Memory map conflict";
		break;
	case SGX_ERROR_DEVICE_BUSY:
		msg = "Device busy";
		break;
	case SGX_ERROR_MODE_INCOMPATIBLE:
		msg = "Mode incompatible";
		break;
	case SGX_ERROR_SERVICE_TIMEOUT:
		msg = "Serice timed out";
		break;
	case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
		msg = "Invalid privilege";
		break;
	case SGX_ERROR_NDEBUG_ENCLAVE:
		msg = "Not debug enclave";
		break;
	case SGX_ERROR_UNDEFINED_SYMBOL:
		msg = "Invalid symbol";
		break;
	case SGX_ERROR_UNEXPECTED:
	default:
		msg = "An unexpeted error occurred";
	}

	return msg;
}

// OCALL to retrieve the current process ID and
// local system time.

void SGX_CDECL ve_o_process_info(uint64_t *ts, uint64_t *pid)
{
	DWORD dwpid = GetCurrentProcessId();
	time_t ltime;

	time(&ltime);

	*ts = (uint64_t)ltime;
	*pid = (uint64_t)dwpid;
}