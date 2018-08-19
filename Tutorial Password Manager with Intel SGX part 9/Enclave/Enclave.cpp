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

#include "Enclave_t.h"
#include "E_Vault.h"
#include "sgx_trts.h"
#include "PasswordManagerError.h"

// There is only one vault in our enclave, so make this a global. Any functions
// that interact with the vault must be called from the main application thread.

E_Vault vault;

int ve_initialize()
{
	return vault.initialize();
}

int ve_initialize_from_header(unsigned char* header, uint16_t len)
{
	return vault.initialize(header, len);
}

int ve_load_vault(unsigned char* edata)
{
	// Make sure our source buffer is outside the enclave
	if (!sgx_is_outside_enclave(edata, vault.get_db_size()))
	{
		return NL_STATUS_INVALID;
	}

	return vault.load_vault(edata);
}

int ve_get_header_size(uint16_t *len)
{
	return vault.get_header(NULL, len);
}

int ve_get_header(unsigned char* header, uint16_t len)
{
	return vault.get_header(header, &len);
}

int ve_get_vault(unsigned char* edata, uint32_t len)
{
	// Make sure our destination buffer is outside the enclave
	if (!sgx_is_outside_enclave(edata, len))
	{
		return NL_STATUS_INVALID;
	}

	return vault.get_vault(edata, &len);
}

uint32_t ve_get_db_size()
{
	return vault.get_db_size();
}

void ve_lock()
{
	return vault.lock();
}

int ve_unlock(char* password)
{
	return vault.unlock(password);
}

int ve_set_master_password(char* password)
{
	return vault.set_master_password(password);
}

int ve_change_master_password(char* oldpass, char* newpass)
{
	return vault.change_master_password(oldpass, newpass);
}

int ve_accounts_get_count(uint32_t* count)
{
	return vault.accounts_get_count(count);
}

int ve_accounts_get_info_sizes(uint32_t idx, uint16_t* mbname_sz, uint16_t* mblogin_sz, uint16_t* mburl_sz)
{
	return vault.accounts_get_info_sizes(idx, mbname_sz, mblogin_sz, mburl_sz);
}

int ve_accounts_get_info(uint32_t idx, char* mbname, uint16_t mbname_sz, char* mblogin, uint16_t mblogin_sz, char* mburl, uint16_t mburl_sz)
{
	return vault.accounts_get_info(idx, mbname, mbname_sz, mblogin, mblogin_sz, mburl, mburl_sz);
}

int ve_accounts_get_password_size(uint32_t idx, uint16_t* mbpass_sz)
{
	return vault.accounts_get_password_size(idx, mbpass_sz);
}

int ve_accounts_get_password(uint32_t idx, char* mbpass, uint16_t mbpass_sz)
{
	return vault.accounts_get_password(idx, mbpass, mbpass_sz);
}

int ve_accounts_set_info(uint32_t idx, char* mbname, uint16_t mbname_len, char* mblogin, uint16_t mblogin_len, char* mburl, uint16_t mburl_len)
{
	return vault.accounts_set_info(idx, mbname, mbname_len, mblogin, mblogin_len, mburl, mburl_len);
}

int ve_accounts_set_password(uint32_t idx, char* mbpass, uint16_t mbpass_len)
{
	return vault.accounts_set_password(idx, mbpass, mbpass_len);
}

int ve_accounts_generate_password(uint16_t length, uint16_t flags, char* cpass)
{
	return vault.accounts_generate_password(length, flags, cpass);
}

int ve_is_valid()
{
	return vault.is_valid();
}

int ve_is_locked()
{
	return vault.is_locked();
}

uint32_t ve_get_state_size()
{
	return vault.get_state_size();
}

int ve_heartbeat(char *state, uint32_t sz)
{
	return vault.heartbeat(state, sz);
}

void ve_set_lock_delay(uint16_t mins)
{
	vault.set_lock_delay(mins);
}

int ve_restore_state(char *state, uint32_t sz)
{
	return vault.restore_state(state, sz);
}