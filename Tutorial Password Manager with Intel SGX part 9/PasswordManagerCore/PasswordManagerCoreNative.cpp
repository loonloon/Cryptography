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
#include "PasswordManagerCoreNative.h"
#include "PasswordManagerError.h"
#include "Pack.h"
#include "Unicode.h"
#undef ENCLAVEBRIDGE_API_EXPORTING
#include "EnclaveBridge.h"
#include <Windows.h>

#pragma unmanaged

using namespace Pack;
using namespace Unicode;

static void CALLBACK clear_clipboard_proc(PVOID param, BOOLEAN fired)
{
	if (!OpenClipboard(NULL))
	{
		return;
	}

	EmptyClipboard();
	CloseClipboard();
}

PasswordManagerCoreNative::PasswordManagerCoreNative(void)
{
	_supports_sgx = 0;
	lock_delay = 0;
	accountdata = NULL;
	timer = NULL;
	vault_state = NULL;
	vault_state_size = 0;
	vault_state_index = -1;
	hb.set_manager(this);
}

PasswordManagerCoreNative::~PasswordManagerCoreNative(void)
{
	if (!OpenClipboard(NULL))
	{
		return;
	}

	EmptyClipboard();
	CloseClipboard();
}

int PasswordManagerCoreNative::ping_vault()
{
	if (supports_sgx())
	{
		return ew_ping();
	}

	return NL_STATUS_OK;
}

// Initialize the state information for handling power
// transitions.
int PasswordManagerCoreNative::init_vault_state()
{
	if (lock_delay == 0)
	{
		return NL_STATUS_INVALID;
	}

	vault_state_index = -1; // Invalidate the state info first.

	if (vault_state == NULL)
	{
		if (supports_sgx())
		{
			int rv;
			rv = ew_get_state_size(&vault_state_size);

			if (rv != NL_STATUS_OK)
			{
				return rv;
			}

			if (vault_state_size == 0)
			{
				return NL_STATUS_UNKNOWN;
			}
		}
		else
		{
			vault_state_size = vault.get_state_size();
		}

		try
		{
			vault_state = new char[vault_state_size * 2];
		}
		catch (...)
		{
			return NL_STATUS_ALLOC;
		}
	}

	SecureZeroMemory(vault_state, vault_state_size * 2);
	hb.start();
	return NL_STATUS_OK;
}

int PasswordManagerCoreNative::set_lock_delay(UINT16 mins)
{
	// If we support Intel SGX, store the timeout in the enclave
	// too (this will be used to generate the cutoff time when
	// building the state block, so we don't have to repeatedly
	// passed a parameter from untrusted memory).
	if (supports_sgx())
	{
		int rv = ew_set_lock_delay(mins);

		// We don't want these out of sync.
		if (rv != NL_STATUS_OK)
		{
			return rv;
		}
	}

	// If the lock timeout is set to zero, then we aren't keeping
	// state. Zero out any state in memory.
	if (mins == 0)
	{
		lock_delay = 0;
		hb.stop();

		clear_vault_state();
		return NL_STATUS_OK;
	}

	lock_delay = (mins > 10) ? 10 : mins;

	// If we have already unlocked the vault, then start the heartbeat.
	if (supports_sgx())
	{
		int locked = 1;
		int valid = 0;
		int rv;
		rv = ew_is_valid(&valid);

		if (rv != NL_STATUS_OK)
		{
			return rv;
		}

		if (valid == 0)
		{
			return NL_STATUS_OK;
		}

		rv = ew_is_locked(&locked);

		if (rv != NL_STATUS_OK)
		{
			return rv;
		}

		if (locked)
		{
			return NL_STATUS_OK;
		}
	}
	else
	{
		if (!vault.is_valid())
		{
			return NL_STATUS_OK;
		}

		if (vault.is_locked())
		{
			return NL_STATUS_OK;
		}
	}

	init_vault_state();
	return NL_STATUS_OK;
}

int PasswordManagerCoreNative::vault_unlock(const LPWSTR wpassphrase)
{
	int rv;
	UINT16 size;
	char *mbpassphrase = tombs(wpassphrase, -1, &size);

	if (mbpassphrase == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	if (supports_sgx())
	{
		rv = ew_unlock(mbpassphrase);
	}
	else
	{
		rv = vault.unlock(mbpassphrase);
	}

	SecureZeroMemory(mbpassphrase, size);
	delete[] mbpassphrase;

	// If we successfully unlock the vault, start the
	// heartbeat timer.
	if (rv == NL_STATUS_OK)
	{
		// If we can't initialize state then we don't keep state.
		if (init_vault_state() != NL_STATUS_OK)
		{
			return rv;
		}
	}

	// Also store this in the enclave.
	if (supports_sgx())
	{
		set_lock_delay(lock_delay);
	}
	else
	{
		vault.set_lock_delay(lock_delay);
	}

	return rv;
}

void PasswordManagerCoreNative::vault_lock(void)
{
	hb.stop();
	clear_vault_state();

	if (supports_sgx())
	{
		ew_lock();
	}
	else
	{
		vault.lock();
	}
}

int PasswordManagerCoreNative::set_master_password(const LPWSTR wpassphrase)
{
	int rv;
	UINT16 size;
	char *mbpassphrase = tombs(wpassphrase, -1, &size);

	if (mbpassphrase == NULL) return NL_STATUS_ALLOC;

	if (supports_sgx()) rv = ew_set_master_password(mbpassphrase);
	else rv = vault.set_master_password(mbpassphrase);

	SecureZeroMemory(mbpassphrase, size);
	delete[] mbpassphrase;
	return rv;
}


int PasswordManagerCoreNative::change_master_password(const LPWSTR wold, const LPWSTR wnew)
{
	int rv = NL_STATUS_ALLOC;
	UINT16 sold, snew;
	char *mbold, *mbnew;
	mbold = tombs(wold, -1, &sold);

	if (mbold == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	mbnew = tombs(wnew, -1, &snew);

	if (mbnew == NULL)
	{
		goto error_alloc_new;
	}

	if (supports_sgx())
	{
		rv = ew_change_master_password(mbold, mbnew);
	}
	else
	{
		rv = vault.change_master_password(mbold, mbnew);
	}

	SecureZeroMemory(mbnew, snew);
	delete[] mbnew;

error_alloc_new:
	SecureZeroMemory(mbold, sold);
	delete[] mbold;

	return rv;
}

int PasswordManagerCoreNative::accounts_get_count(UINT32 *num)
{
	if (supports_sgx())
	{
		return ew_accounts_get_count(num);
	}

	return vault.accounts_get_count(num);
}

int PasswordManagerCoreNative::accounts_get_info(UINT32 idx, LPWSTR *wname, LPWSTR *wlogin, LPWSTR *wurl)
{
	int rv;
	char *mbname, *mblogin, *mburl;
	UINT16 sname, slogin, surl, lwname, lwlogin, lwurl;

	// Get the buffer sizes needed to hold each field + NULL byte
	if (supports_sgx())
	{
		rv = ew_accounts_get_info_sizes(idx, &sname, &slogin, &surl);
	}
	else
	{
		rv = vault.accounts_get_info_sizes(idx, &sname, &slogin, &surl);
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// Allocation and error-handling block
	mbname = new char[sname];

	if (mbname == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	mblogin = new char[slogin];

	if (mblogin == NULL)
	{
		goto error_alloc_login;
	}

	mburl = new char[surl];

	if (mburl == NULL)
	{
		goto error_alloc_url;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_get_info(idx, mbname, sname, mblogin, slogin, mburl, surl);
	}
	else
	{
		rv = vault.accounts_get_info(idx, mbname, sname, mblogin, slogin, mburl, surl);
	}

	if (rv == NL_STATUS_OK)
	{
		// Convert to LPWST's if the call was successful.
		// Make sure we don't leave memory allocated if
		// we get a failure when creating any of them.
		*wname = towchar(mbname, sname, &lwname);

		if (*wname == NULL)
		{
			rv = NL_STATUS_ALLOC;
		}

		if (rv == NL_STATUS_OK)
		{
			*wlogin = towchar(mblogin, slogin, &lwlogin);

			if (*wlogin == NULL)
			{
				rv = NL_STATUS_ALLOC;
				SecureZeroMemory(*wname, lwname * sizeof(wchar_t));
				delete[] * wname;
			}
		}

		if (rv == NL_STATUS_OK)
		{
			*wurl = towchar(mburl, surl, &lwurl);

			if (*wurl == NULL)
			{
				rv = NL_STATUS_ALLOC;
				SecureZeroMemory(*wname, lwname * sizeof(wchar_t));
				delete[] * wname;
				SecureZeroMemory(*wlogin, lwlogin * sizeof(wchar_t));
				delete[] * wlogin;
			}
		}
	}

	SecureZeroMemory(mburl, surl);
	delete[] mburl;

error_alloc_url:
	SecureZeroMemory(mblogin, slogin);
	delete[] mblogin;

error_alloc_login:
	SecureZeroMemory(mbname, sname);
	delete[] mbname;

	return rv;
}

void PasswordManagerCoreNative::accounts_release_info(LPWSTR wname, LPWSTR wlogin, LPWSTR wurl)
{
	SecureZeroMemory(wname, wcslen(wname) * sizeof(wchar_t));
	SecureZeroMemory(wlogin, wcslen(wlogin) * sizeof(wchar_t));
	SecureZeroMemory(wurl, wcslen(wurl) * sizeof(wchar_t));
	delete[] wname;
	delete[] wlogin;
	delete[] wurl;
}

// First get the size needed to hold the password, then allocate memory and fetch it.
int PasswordManagerCoreNative::accounts_get_password(UINT32 idx, LPWCH *wpass, UINT16 *wlen)
{
	int rv;
	char *mbpass;
	UINT16 mbsz;

	if (supports_sgx())
	{
		rv = ew_accounts_get_password_size(idx, &mbsz);
	}
	else
	{
		rv = vault.accounts_get_password_size(idx, &mbsz);
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	mbpass = new char[mbsz];

	if (mbpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_get_password(idx, mbpass, mbsz);
	}
	else
	{
		rv = vault.accounts_get_password(idx, mbpass, mbsz);
	}

	if (rv != NL_STATUS_OK)
	{
		delete[] mbpass;
		return rv;
	}

	// Convert to wchar_t *. Check for NULL further down.
	*wpass = towchar(mbpass, mbsz, wlen);

	// Erase and free the char* version
	SecureZeroMemory(mbpass, mbsz);
	delete[] mbpass;

	return (*wpass == NULL) ? NL_STATUS_ALLOC : NL_STATUS_OK;
}

int PasswordManagerCoreNative::accounts_view_password(UINT32 idx, HWND hWnd)
{
	int rv = NL_STATUS_UNKNOWN;
	LPWCH wpass;
	UINT16 wlen;
	static const wchar_t empty[] = L"(no password stored)";

	// First get the password
	rv = this->accounts_get_password(idx, &wpass, &wlen);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// Display our MessageBox
	MessageBox(hWnd, (wlen > 1) ? wpass : empty, L"Password", MB_OK);
	this->accounts_release_password(wpass, wlen);
	return rv;
}

int PasswordManagerCoreNative::accounts_password_to_clipboard(UINT32 idx)
{
	int rv = NL_STATUS_UNKNOWN;
	UINT32 wsz, wlen;
	char *mbpass;
	HGLOBAL hmem = NULL;
	wchar_t *gmem = NULL;
	UINT16 mbsz;

	if (supports_sgx())
	{
		rv = ew_accounts_get_password_size(idx, &mbsz);
	}
	else
	{
		rv = vault.accounts_get_password_size(idx, &mbsz);
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	mbpass = new char[mbsz];

	if (supports_sgx())
	{
		rv = ew_accounts_get_password(idx, mbpass, mbsz);
	}
	else
	{
		rv = vault.accounts_get_password(idx, mbpass, mbsz);
	}

	if (rv != NL_STATUS_OK)
	{
		delete[] mbpass;
		return rv;
	}

	wlen = (UINT16)MultiByteToWideChar(CP_UTF8, 0, mbpass, mbsz, NULL, 0);
	wsz = (wlen + 1) * sizeof(wchar_t);

	hmem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, wsz);

	if (hmem != NULL)
	{
		gmem = (wchar_t *)GlobalLock(hmem);
	}

	if (gmem == NULL)
	{
		SecureZeroMemory(mbpass, mbsz);
		delete[] mbpass;
		return NL_STATUS_ALLOC;
	}

	// Convert the multibyte password into a wchar_t directly in the global memory area
	MultiByteToWideChar(CP_UTF8, 0, mbpass, mbsz, gmem, wlen);
	GlobalUnlock(hmem);

	// Erase and free the char* version
	SecureZeroMemory(mbpass, mbsz);
	delete[] mbpass;

	// Fails if the clipboard is already open. Should consider
	// retrying a couple of times here before giving up.
	if (!OpenClipboard(NULL))
	{
		rv = NL_STATUS_CLIPBOARD;
	}
	else
	{
		EmptyClipboard();

		if (SetClipboardData(CF_UNICODETEXT, gmem) == NULL)
		{
			rv = NL_STATUS_CLIPBOARD;
			SecureZeroMemory(gmem, wsz);
			GlobalFree(gmem);
		}
		else
		{
			rv = NL_STATUS_OK;
			this->start_clipboard_timer();
		}

		CloseClipboard();
	}

	return rv;
}

void PasswordManagerCoreNative::start_clipboard_timer()
{
	// Use the default Timer Queue
	// Stop any existing timer
	if (timer != NULL)
	{
		DeleteTimerQueueTimer(NULL, timer, NULL);
	}

	// Start a new timer
	if (!CreateTimerQueueTimer(&timer, NULL, (WAITORTIMERCALLBACK)clear_clipboard_proc,
		NULL, CLIPBOARD_CLEAR_SECS * 1000, 0, 0))
	{
		return;
	}
}

void PasswordManagerCoreNative::accounts_release_password(LPWCH pw, UINT16 w_pw_len)
{
	SecureZeroMemory(pw, w_pw_len * sizeof(wchar_t));
	delete[] pw;
}

// Pass by reference because we don't want to make copies of these.

int PasswordManagerCoreNative::accounts_set_info(UINT32 idx, const LPWSTR wname, const LPWSTR wlogin, const LPWSTR wurl)
{
	int rv = NL_STATUS_ALLOC;
	char *mbname, *mblogin, *mburl;
	UINT16 lname, llogin, lurl;

	mbname = tombs(wname, -1, &lname);

	if (mbname == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	mblogin = tombs(wlogin, -1, &llogin);

	if (mblogin == NULL)
	{
		goto error_alloc_login;
	}

	mburl = tombs(wurl, -1, &lurl);

	if (mburl == NULL)
	{
		goto error_alloc_url;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_set_info(idx, mbname, lname, mblogin, llogin, mburl, lurl);
	}
	else
	{
		rv = vault.accounts_set_info(idx, mbname, lname, mblogin, llogin, mburl, lurl);
	}

	SecureZeroMemory(mburl, lurl);
	delete[] mburl;

error_alloc_url:
	SecureZeroMemory(mblogin, llogin);
	delete[] mblogin;

error_alloc_login:
	SecureZeroMemory(mbname, lname);
	delete[] mbname;

	return rv;
}

int PasswordManagerCoreNative::accounts_set_password(UINT32 idx, const LPWSTR wpassphrase)
{
	int rv;
	UINT16 size;

	/* char *mbpassphrase = tombs(wpassphrase, (UINT32) wcslen(wpassphrase), &size); // We don't want the NULL byte here */
	char *mbpassphrase = tombs(wpassphrase, -1, &size); // We don't want the NULL byte here

	if (mbpassphrase == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_set_password(idx, mbpassphrase, size);
	}
	else
	{
		rv = vault.accounts_set_password(idx, mbpassphrase, size);
	}

	SecureZeroMemory(mbpassphrase, size);
	delete[] mbpassphrase;
	return rv;
}

int PasswordManagerCoreNative::accounts_generate_password(UINT16 length, UINT16 flags, LPWSTR *wpass, UINT16 *wlen)
{
	int rv;
	char *cpass;
	cpass = new char[length + 1];

	if (cpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_generate_password(length, flags, cpass);
	}
	else
	{
		rv = vault.accounts_generate_password(length, flags, cpass);
	}

	cpass[length] = NULL;

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	*wpass = towchar(cpass, length + 1, wlen);
	SecureZeroMemory(cpass, length);
	delete[] cpass;

	return (*wpass == NULL) ? NL_STATUS_ALLOC : NL_STATUS_OK;
}

int PasswordManagerCoreNative::accounts_generate_and_view_password(UINT16 length, UINT16 flags, LPWSTR *wpass, UINT16 *wlen, HWND hWnd)
{
	int rv;
	char *cpass;
	int dresult = 0;
	cpass = new char[length + 1];

	if (cpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	if (supports_sgx())
	{
		rv = ew_accounts_generate_password(length, flags, cpass);
	}
	else
	{
		rv = vault.accounts_generate_password(length, flags, cpass);
	}

	cpass[length] = NULL;

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	*wpass = towchar(cpass, length + 1, wlen);
	SecureZeroMemory(cpass, length);
	delete[] cpass;

	if (*wpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	// Show the message box
	dresult = MessageBox(hWnd, *wpass, L"Accept this password?", MB_YESNOCANCEL);

	if (dresult == IDNO)
	{
		return NL_STATUS_AGAIN;
	}
	else if (dresult == IDYES)
	{
		return NL_STATUS_OK;
	}

	// User canceled, or the window was killed.
	return NL_STATUS_USER_CANCEL;
}

int PasswordManagerCoreNative::initialize_vault(void)
{
	// Power events impacting Intel SGX are handled seamlessly in EnclaveBridge
	if (supports_sgx())
	{
		return ew_initialize();
	}

	return vault.initialize();
}

int PasswordManagerCoreNative::initialize_vault(const PBYTE header, UINT16 size)
{
	// Power events impacting Intel SGX are handled seamlessly in EnclaveBridge
	if (supports_sgx())
	{
		return ew_initialize_from_header((const char *)header, size);
	}

	return vault.initialize(header, size);
}

int PasswordManagerCoreNative::load_vault(const PBYTE edata)
{
	if (supports_sgx())
	{
		return ew_load_vault(edata);
	}
	else
	{
		return vault.load_vault(edata);
	}
}

int PasswordManagerCoreNative::get_vault_data(PBYTE edata, UINT32 *size)
{
	if (supports_sgx())
	{
		return ew_get_vault(edata, size);
	}

	return vault.get_vault(edata, size);
}

int PasswordManagerCoreNative::get_vault_header(PBYTE header, UINT16 *size)
{
	if (supports_sgx())
	{
		return ew_get_header(header, size);
	}

	return vault.get_header(header, size);
}

// Perform our heartbeat. Get the vault state and save it, but
// do so atomically: we need to ensure that we don't corrupt
// our application if a power change occurs in the middle of a 
// state update (this should only impact the Intel SGX state
// but the generic implementation, below, applies to all)
int PasswordManagerCoreNative::heartbeat()
{
	int next_index;
	char *bp;

	next_index = (vault_state_index != 0) ? 0 : 1;
	bp = &vault_state[vault_state_size*next_index];

	if (supports_sgx())
	{
		int rv = ew_heartbeat(bp, vault_state_size);

		// If this ECALL fails, don't update the state info.
		// This will also stop the heartbeat.
		if (rv != NL_STATUS_OK)
		{
			if (rv == NL_STATUS_LOST_ENCLAVE)
			{
				return 0;
			}

			return 1;
		}
	}
	else
	{
		vault.heartbeat(bp);
	}

	// Our atomic operation which officially changes our state.
	vault_state_index = next_index;
	return 1;
}

void PasswordManagerCoreNative::clear_vault_state()
{
	if (vault_state_index != -1)
	{
		vault_state_index = -1;
		SecureZeroMemory(vault_state, vault_state_size * 2);
	}
}

int PasswordManagerCoreNative::restore_vault_state()
{
	int rv;
	hb.stop();

	// If there is no state, then the vault should be locked.
	// Return NL_STATUS_PERM
	if (vault_state_index == -1)
	{
		return NL_STATUS_PERM;
	}

	if (supports_sgx())
	{
		// Restore the vault state in the enclave
		rv = ew_restore_state(&vault_state[vault_state_size*vault_state_index], vault_state_size);

		// We don't support recovering from a power event in the middle of 
		// recovering from the previous power event.
		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			return NL_STATUS_LOST_ENCLAVE;
		}
	}
	else
	{
		rv = vault.check_state(&vault_state[vault_state_size*vault_state_index], vault_state_size);
	}

	if (rv == NL_STATUS_OK)
	{
		hb.start();
		return rv;
	}

	// Any other return code? The vault is considered locked.
	return NL_STATUS_PERM;
}

int PasswordManagerCoreNative::check_vault_state()
{
	if (supports_sgx())
	{
		return NL_STATUS_INVALID;
	}

	// If there is no state, then the vault should remain locked.
	// Return NL_STATUS_PERM
	if (vault_state_index == -1)
	{
		return NL_STATUS_PERM;
	}

	if (vault.check_state(&vault_state[vault_state_size*vault_state_index], vault_state_size))
	{
		return NL_STATUS_OK;
	}

	return NL_STATUS_INVALID;
}

void PasswordManagerCoreNative::finalize_restore_vault_state()
{
	init_vault_state();
}

// Immediately stop the heartbeats when we suspend.
void PasswordManagerCoreNative::suspend()
{
	hb.stop();
}

const char *PasswordManagerCoreNative::sgx_error_string()
{
	return ew_sgx_error_string();
}


