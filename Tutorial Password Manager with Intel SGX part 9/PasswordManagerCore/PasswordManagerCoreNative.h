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

#include "common.h"
#include "dllexport.h"
#include "Vault.h"
#include "Heartbeat.h"
#include <Windows.h>
#include <string.h>
#include <cwchar>

using namespace std;

class PASSWORDMANAGERCORE_API PasswordManagerCoreNative
{
	int _supports_sgx;
	Vault vault;
	PBYTE accountdata;
	Heartbeat hb;
	friend ref class PasswordManagerCore;
	friend class Heartbeat;
	HANDLE timer;
	UINT32 vault_state_size;
	UINT16 lock_delay;	// In minutes

	void start_clipboard_timer(void);
	int vault_state_index;
	char *vault_state;

	int init_vault_state();
	void clear_vault_state();

public:
	PasswordManagerCoreNative(void);
	~PasswordManagerCoreNative(void);

	int heartbeat();

protected:
	void set_sgx_support(void) { _supports_sgx = 1; }
	int supports_sgx(void)
	{
		return _supports_sgx;
	}

	int ping_vault(void);

	int initialize_vault(void);
	int initialize_vault(const PBYTE header, UINT16 size);
	int load_vault(const PBYTE edata);

	int get_vault_data(PBYTE edata, UINT32 *size);
	int get_vault_header(PBYTE header, UINT16 *size);

	int vault_unlock(const LPWSTR passphrase);
	void vault_lock(void);

	int set_master_password(const LPWSTR password);
	int change_master_password(const LPWSTR oldpass, const LPWSTR newpass);

	int accounts_get_count(UINT32 *count);
	int accounts_get_info(UINT32 idx, LPWSTR *name, LPWSTR *login, LPWSTR *url);
	void accounts_release_info(LPWSTR name, LPWSTR login, LPWSTR url);

	int accounts_get_password(UINT32 idx, LPWSTR *pw, UINT16 *pw_size);
	int accounts_view_password(UINT32 idx, HWND hWnd);
	int accounts_password_to_clipboard(UINT32 idx);

	void accounts_release_password(LPWSTR pw, UINT16 wpw_size);

	int accounts_set_info(UINT32 idx, const LPWSTR name, const LPWSTR login, const LPWSTR url);
	int accounts_set_password(UINT32 idx, const LPWSTR pass);

	int accounts_generate_password(UINT16 length, UINT16 flags, LPWSTR *pass, UINT16 *wlen);
	int accounts_generate_and_view_password(UINT16 length, UINT16 flags, LPWSTR *pass, UINT16 *wlen, HWND hWnd);

	int set_lock_delay(UINT16 mins);

	void suspend();

	int restore_vault_state();
	int check_vault_state();
	void finalize_restore_vault_state();

	const char *sgx_error_string();
};
