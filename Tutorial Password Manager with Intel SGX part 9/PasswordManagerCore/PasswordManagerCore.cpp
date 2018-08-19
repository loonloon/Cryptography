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
#include <Windows.h>
#include <vcclr.h>
#include "PasswordManagerCore.h"
#include "PasswordManagerCoreNative.h"
#include "PasswordManagerError.h"
#include "VaultFile.h"
#include "Unicode.h"

using namespace System;
using namespace System::Runtime::InteropServices;
using namespace System::Security;
using namespace System::Drawing;

using namespace Unicode;

PasswordManagerCore::PasswordManagerCore()
{
	_nlink = new PasswordManagerCoreNative();
	vaultfile = gcnew VaultFile();
	cache_accounts = _NL_CACHE_STALE;
	restore_rv = false;
}

PasswordManagerCore::~PasswordManagerCore()
{
	delete _nlink;
	_nlink = NULL;
	vaultfile->close();
}

void PasswordManagerCore::set_sgx_support()
{
	_nlink->set_sgx_support();
}

int PasswordManagerCore::vault_create(String ^path)
{
	int rv = vaultfile->create(path);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// Initialize an empty vault
	return _nlink->initialize_vault();
}

int PasswordManagerCore::vault_open(String ^path)
{
	int rv = vaultfile->open_read(path);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	return this->_vault_initialize();
}

int PasswordManagerCore::_vault_initialize()
{
	array<Byte> ^header;

	// Initialize the vault
	header = vaultfile->get_header();
	UInt16 header_size = vaultfile->get_header_size();
	PBYTE cheader = new BYTE[header_size];

	if (cheader == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	try
	{
		Marshal::Copy(header, 0, IntPtr(cheader), header_size);
	}
	catch (...)
	{
		return NL_STATUS_ALLOC;
	}

	int rv = _nlink->initialize_vault(cheader, header_size);
	delete[] cheader;
	return rv;
}

int PasswordManagerCore::_vault_reinitialize()
{
	if (!vaultfile->is_open())
	{
		return NL_STATUS_INVALID;
	}

	return this->_vault_initialize();
}

int PasswordManagerCore::vault_unlock(SecureString ^passphrase)
{
	int retries = 3;
	int rv;

	// Retry if a power event brings down the Intel SGX enclave
	// (max of 3 retries).
	while (retries--)
	{
		rv = _vault_unlock(passphrase);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			// Reinitialize the enclave and vault from the data file and try again
			rv = _vault_reinitialize();

			if (rv != NL_STATUS_OK)
			{
				return NL_STATUS_LOST_ENCLAVE;
			}
		}
		else
		{
			return rv;
		}
	}

	return rv;
}

int PasswordManagerCore::_vault_unlock(SecureString ^passphrase)
{
	int rv;

	if (vaultfile->is_new())
	{
		return NL_STATUS_INVALID;
	}

	if (!vaultfile->is_open())
	{
		rv = vaultfile->open_read(vaultfile->get_vault_path());
		if (rv != NL_STATUS_OK) return rv;
	}

	LPWSTR wpassphrase = M_SecureString_to_LPWSTR(passphrase);

	if (wpassphrase == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	rv = _nlink->vault_unlock(wpassphrase);
	M_Free_LPWSTR(wpassphrase);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	return send_vault_data();
}

int PasswordManagerCore::send_vault_data()
{
	PBYTE edata;
	int rv, vault_size;
	array<Byte> ^evaultdata;

	vault_size = (int)vaultfile->get_vault_size();
	evaultdata = gcnew array<Byte>(vault_size);
	rv = vaultfile->get_vault(evaultdata);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// Send this to the vault for decrypting
	edata = new BYTE[vault_size];

	if (edata == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	// Marshal the data block
	try
	{
		Marshal::Copy(evaultdata, 0, IntPtr(edata), vault_size);
	}
	catch (...)
	{
		return NL_STATUS_ALLOC;
	}

	rv = _nlink->load_vault(edata);
	delete[] edata;
	return rv;
}

void PasswordManagerCore::vault_lock()
{
	this->_nlink->vault_lock();
	vaultfile->close();
}

int PasswordManagerCore::set_master_password(SecureString ^password, SecureString ^confirm)
{
	LPWSTR wpass, wconfirm;
	int rv;

	wpass = M_SecureString_to_LPWSTR(password);

	if (wpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	wconfirm = M_SecureString_to_LPWSTR(confirm);

	if (wconfirm == NULL)
	{
		M_Free_LPWSTR(wpass);
		return NL_STATUS_ALLOC;
	}

	if (lstrcmpW(wpass, wconfirm))
	{
		rv = NL_STATUS_MISMATCH;
	}
	else
	{
		// Need a special case if the power event happens on a newly-
		// created vault. The file has been created, but nothing
		// has been written to it yet. Keep the original path, 
		// just reinitialize the vault info/header in memory.

		int tries = 3;

		while (tries--)
		{
			rv = _nlink->set_master_password(wpass);

			if (rv == NL_STATUS_RECREATED_ENCLAVE)
			{
				// Reinitialize the vault
				rv = _nlink->initialize_vault();

				if (rv != NL_STATUS_OK)
				{
					rv = NL_STATUS_LOST_ENCLAVE;
					tries = 0;
				}
			}
			else break;
		}
	}

	M_Free_LPWSTR(wconfirm);
	M_Free_LPWSTR(wpass);

	if (rv == NL_STATUS_OK)
	{
		return this->update_vault();
	}

	return rv;
}

int PasswordManagerCore::change_master_password(SecureString ^oldpass, SecureString ^newpass, SecureString ^confirm)
{
	LPWSTR wold, wnew, wconfirm;
	int rv;

	wold = M_SecureString_to_LPWSTR(oldpass);

	if (wold == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	wnew = M_SecureString_to_LPWSTR(newpass);

	if (wnew == NULL)
	{
		M_Free_LPWSTR(wold);
		return NL_STATUS_ALLOC;
	}

	wconfirm = M_SecureString_to_LPWSTR(confirm);

	if (wconfirm == NULL)
	{
		M_Free_LPWSTR(wold);
		M_Free_LPWSTR(wnew);
		return NL_STATUS_ALLOC;
	}

	if (lstrcmpW(wnew, wconfirm))
	{
		rv = NL_STATUS_MISMATCH;
	}
	else if (!lstrcmpW(wnew, wold))
	{
		rv = NL_STATUS_NO_CHANGE;
	}
	else
	{
		int tries = 3;

		while (tries--)
		{
			rv = _nlink->change_master_password(wold, wnew);

			if (rv == NL_STATUS_RECREATED_ENCLAVE)
			{
				if (!restore_vault())
				{
					rv = NL_STATUS_LOST_ENCLAVE;
					tries = 0;
				}
			}
			else
			{
				break;
			}
		}
	}

	M_Free_LPWSTR(wold);
	M_Free_LPWSTR(wnew);
	M_Free_LPWSTR(wconfirm);

	if (rv == NL_STATUS_OK)
	{
		return this->update_vault();
	}

	return rv;
}

int PasswordManagerCore::accounts_get_count(UInt32 %count)
{
	UINT32 c;
	int rv;
	int tries = 3;

	while (tries--)
	{
		rv = _nlink->accounts_get_count(&c);
		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	count = c;
	return NL_STATUS_OK;
}

// Gets the account information for the account with index idx.
//
// Behind the scenes, instead of individually marshalling the account data one account at a time, we pull in all
// of it at once and then fetch the individual accounts from the local cache.
int PasswordManagerCore::accounts_get_info(UInt32 idx, SecureString ^%name, SecureString ^%login, SecureString ^%url)
{
	int rv;
	UINT32 index = idx;
	wchar_t *wname, *wlogin, *wurl;
	int tries = 3;

	while (tries--)
	{
		rv = _nlink->accounts_get_info(index, &wname, &wlogin, &wurl);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	if (rv == NL_STATUS_OK)
	{
		try
		{
			name = gcnew SecureString(wname, (int)wcslen(wname));
			login = gcnew SecureString(wlogin, (int)wcslen(wlogin));
			url = gcnew SecureString(wurl, (int)wcslen(wurl));
		}
		catch (...)
		{
			rv = NL_STATUS_ALLOC;
		}

		_nlink->accounts_release_info(wname, wlogin, wurl);
	}

	return rv;
}

int PasswordManagerCore::accounts_view_password(UInt32 idx, IntPtr hptr)
{
	int rv;
	UINT32 index = idx;
	HWND hWnd = static_cast<HWND>(hptr.ToPointer());
	int tries = 3;

	while (tries--)
	{
		rv = _nlink->accounts_view_password(index, hWnd);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	return rv;
}

int PasswordManagerCore::accounts_get_password(UInt32 idx, SecureString ^%password)
{
	int rv;
	wchar_t *wpass;
	UINT16 wpass_len;
	UINT32 index = idx;
	int tries = 3;

	while (tries--)
	{
		rv = _nlink->accounts_get_password(index, &wpass, &wpass_len);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	password->Clear();

	for (int i = 0; i < wpass_len - 1; ++i)
	{
		// Don't include the NULL byte
		password->AppendChar(wpass[i]);
	}

	_nlink->accounts_release_password(wpass, wpass_len);
	return rv;
}

int PasswordManagerCore::accounts_password_to_clipboard(UInt32 idx)
{
	UINT32 index = idx;
	int rv;
	int tries = 3;

	while (tries--)
	{
		rv = _nlink->accounts_password_to_clipboard(index);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	return rv;
}

int PasswordManagerCore::accounts_set_info(UInt32 idx, SecureString ^name, SecureString ^login, SecureString ^url)
{
	LPWSTR wname, wlogin, wurl;
	UINT32 index = idx;
	int rv = NL_STATUS_ALLOC;
	int tries = 3;

	wname = M_SecureString_to_LPWSTR(name);

	if (wname == NULL)
	{
		return rv;
	}

	wlogin = M_SecureString_to_LPWSTR(login);

	if (wlogin == NULL)
	{
		goto error_alloc_login;
	}

	wurl = M_SecureString_to_LPWSTR(url);

	if (wlogin == NULL)
	{
		goto error_alloc_url;
	}

	while (tries--)
	{
		rv = _nlink->accounts_set_info(index, wname, wlogin, wurl);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	M_Free_LPWSTR(wurl);
error_alloc_url:
	M_Free_LPWSTR(wlogin);
error_alloc_login:
	M_Free_LPWSTR(wname);

	if (rv == NL_STATUS_OK)
	{
		return this->update_vault();
	}

	return rv;
}

int PasswordManagerCore::accounts_set_password(UInt32 idx, SecureString ^password)
{
	int rv;
	LPWSTR wpass;
	UINT32 index = idx;
	int tries = 3;

	wpass = M_SecureString_to_LPWSTR(password);

	if (wpass == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	while (tries--)
	{
		rv = _nlink->accounts_set_password(index, wpass);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	M_Free_LPWSTR(wpass);

	if (rv == NL_STATUS_OK)
	{
		return this->update_vault();
	}

	return rv;
}

int PasswordManagerCore::generate_and_view_password(UInt16 mlength, UInt16 mflags, SecureString ^%password, IntPtr hptr)
{
	int rv = NL_STATUS_AGAIN;
	LPWSTR wpass;
	UINT16 wlen;
	UINT16 length = mlength;
	UINT16 flags = mflags;
	HWND hWnd = static_cast<HWND>(hptr.ToPointer());

	if (!length)
	{
		return NL_STATUS_INVALID;
	}

	// Loop until they accept the randomly generated password, cancel, or an error occurs.
	while (rv == NL_STATUS_AGAIN)
	{
		int tries = 3;

		while (tries--)
		{
			rv = _nlink->accounts_generate_and_view_password(length, flags, &wpass, &wlen, hWnd);

			if (rv == NL_STATUS_RECREATED_ENCLAVE)
			{
				if (!restore_vault())
				{
					rv = NL_STATUS_LOST_ENCLAVE;
					tries = 0;
				}
			}
			else
			{
				tries = 0;
			}
		}

		// Each loop through here allocates a new pointer.
		if (rv == NL_STATUS_AGAIN)
		{
			_nlink->accounts_release_password(wpass, wlen);
		}
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// They accepted this password, so assign it and return.
	password->Clear();

	for (int i = 0; i < length; ++i)
	{
		password->AppendChar(wpass[i]);
	}

	_nlink->accounts_release_password(wpass, wlen);
	return rv;
}

int PasswordManagerCore::generate_password(UInt16 mlength, UInt16 mflags, SecureString ^%password)
{
	int rv;
	LPWSTR wpass;
	UINT16 wlen;
	UINT16 length = mlength;
	UINT16 flags = mflags;
	int tries = 3;

	if (!length)
	{
		return NL_STATUS_INVALID;
	}

	while (tries--)
	{
		rv = _nlink->accounts_generate_password(length, flags, &wpass, &wlen);

		if (rv == NL_STATUS_RECREATED_ENCLAVE)
		{
			if (!restore_vault())
			{
				rv = NL_STATUS_LOST_ENCLAVE;
				tries = 0;
			}
		}
		else
		{
			break;
		}
	}

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	password->Clear();

	for (int i = 0; i < length; ++i)
	{
		password->AppendChar(wpass[i]);
	}

	_nlink->accounts_release_password(wpass, wlen);
	return rv;
}

// If we have a power event and lose the enclave 
// in the update_vault() method, before the vault 
// data can be read from it, we are in trouble. 
// We can restore the vault to its previous state 
// on disk, but the most recent update will be
// lost.
int PasswordManagerCore::update_vault()
{
	array<Byte> ^header;
	array<Byte> ^vault;
	UINT16 hsz;
	UINT32 vsz;
	unsigned char *data;
	int rv;

	//-----------------------------------------
	// Get the vault first, because this updates the
	// nonce and the tag, which is stored in the
	// header
	//-----------------------------------------
	rv = _nlink->get_vault_data(NULL, &vsz);

	if (rv == NL_STATUS_RECREATED_ENCLAVE)
	{
		return restore_vault() ? NL_STATUS_UPDATE : NL_STATUS_LOST_ENCLAVE;
	}
	else if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	data = new BYTE[vsz];

	if (data == NULL)
	{
		return NL_STATUS_UPDATE;
	}

	rv = _nlink->get_vault_data(data, &vsz);

	if (rv == NL_STATUS_RECREATED_ENCLAVE)
	{
		return restore_vault() ? NL_STATUS_UPDATE : NL_STATUS_LOST_ENCLAVE;
	}
	else if (rv != NL_STATUS_OK)
	{
		return NL_STATUS_UPDATE;
	}

	// Marshal the data block
	vault = gcnew array<Byte>(vsz);

	try
	{
		Marshal::Copy(IntPtr(data), vault, 0, vsz);
	}
	catch (...)
	{
		return NL_STATUS_UPDATE;
	}
	finally
	{
		delete[] data;
	}

	//-----------------------------------------
	// Now get the header 
	//-----------------------------------------
	rv = _nlink->get_vault_header(NULL, &hsz);

	if (rv == NL_STATUS_RECREATED_ENCLAVE)
	{
		return restore_vault() ? NL_STATUS_UPDATE : NL_STATUS_LOST_ENCLAVE;
	}
	else if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	data = new BYTE[hsz];

	if (data == NULL)
	{
		return NL_STATUS_UPDATE;
	}

	rv = _nlink->get_vault_header(data, &hsz);

	if (rv == NL_STATUS_RECREATED_ENCLAVE)
	{
		return restore_vault() ? NL_STATUS_UPDATE : NL_STATUS_LOST_ENCLAVE;
	}
	else if (rv != NL_STATUS_OK)
	{
		return NL_STATUS_UPDATE;
	}

	// Marshal the data block
	header = gcnew array<Byte>(hsz);

	try
	{
		Marshal::Copy(IntPtr(data), header, 0, hsz);
	}
	catch (...)
	{
		return NL_STATUS_UPDATE;
	}
	finally
	{
		delete[] data;
	}

	// Updating the vault is a multi-step process:
	// 1. Open a temp copy
	// 2. Write the header
	// 3. Write the encrypted vault data
	// 4. Close
	// 5. Replace the original
	rv = (vaultfile->open_write());

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	rv = vaultfile->write_data(header);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	rv = vaultfile->write_data(vault);

	if (rv != NL_STATUS_OK)
	{
		return rv;
	}

	// Now finish up
	return vaultfile->finish_write();
}

// Restore the vault state to the enclave after a power event.
bool PasswordManagerCore::restore_vault(bool flag_async)
{
	bool got_lock = false;
	int rv;

	// Only let one thread do the restore if both come in at the 
	// same time. A spinlock approach is inefficient but simple.
	// This is OK for our application, but a high-performance
	// application (or one with a long-running work loop)
	// would want something else.
	try
	{
		slock.Enter(got_lock);

		if (_nlink->supports_sgx())
		{
			bool do_restore = true;

			// This part is only needed for enclave-based vaults.
			if (flag_async)
			{
				// If we are entering as a result of a power event,
				// make sure the vault has not already been restored
				// by the synchronous/UI thread (ie, a failed ECALL).
				rv = _nlink->ping_vault();

				if (rv != NL_STATUS_LOST_ENCLAVE)
				{
					do_restore = false;
				}

				// If do_store is false, then we'll also use the
				// last value of rv_restore as our return value.
				// This will tell us whether or not we should lock the
				// vault.
			}

			if (do_restore)
			{
				// If the vaultfile isn't open then we are locked or hadn't
				// been opened to be begin with.
				if (!vaultfile->is_open())
				{
					// Have we opened a vault yet?
					if (vaultfile->get_vault_path()->Length == 0)
					{
						goto restore_error;
					}

					// We were explicitly locked, so reopen.
					rv = vaultfile->open_read(vaultfile->get_vault_path());

					if (rv != NL_STATUS_OK)
					{
						goto restore_error;
					}
				}

				// Reinitialize the vault from the header.
				rv = _vault_reinitialize();

				if (rv != NL_STATUS_OK)
				{
					goto restore_error;
				}

				// Now, call to the native object to restore the vault state.
				rv = _nlink->restore_vault_state();

				if (rv != NL_STATUS_OK)
				{
					goto restore_error;
				}

				// The database password was restored to the vault. Now restore
				// the vault, itself.
				rv = send_vault_data();

			restore_error:
				restore_rv = (rv == NL_STATUS_OK);
			}
		}
		else
		{
			rv = _nlink->check_vault_state();
			restore_rv = (rv == NL_STATUS_OK);
		}

		slock.Exit(false);
	}
	catch (...)
	{
		// We don't need to do anything here.		
	}

	return restore_rv;
}

void PasswordManagerCore::suspend()
{
	_nlink->suspend();
}

int PasswordManagerCore::resume()
{
	return restore_vault(true) ? RESUME_UNLOCKED : RESUME_LOCKED;
}

String ^PasswordManagerCore::error_msg(int code)
{
	if (code == NL_STATUS_SGXERROR)
	{
		const char *cmsg = _nlink->sgx_error_string();
		return gcnew String(cmsg);
	}

	switch (code)
	{
	case NL_STATUS_ALLOC:
		return gcnew String("Out of memory");
		break;
	case NL_STATUS_BADFILE:
		return gcnew String("Invalid vault file");
		break;
	case NL_STATUS_CLIPBOARD:
		return gcnew String("Clipboard operation failed");
		break;
	case NL_STATUS_EXISTS:
		return gcnew String("Target exists");
		break;
	case NL_STATUS_INVALID:
		return gcnew String("Invalid parameter");
		break;
	case NL_STATUS_LOST_ENCLAVE:
		return gcnew String("Enclave lost");
		break;
	case NL_STATUS_NOTFOUND:
		return gcnew String("Entry not found");
		break;
	case NL_STATUS_NO_CHANGE:
		return gcnew String("No changes");
		break;
	case NL_STATUS_OK:
		return gcnew String("No error");
		break;
	case NL_STATUS_PASSWORD:
		return gcnew String("Password incorrect");
		break;
	case NL_STATUS_PERM:
		return gcnew String("Permission denied");
		break;
	case NL_STATUS_RAND:
		return gcnew String("Random numbers unavailable");
		break;
	case NL_STATUS_RANGE:
		return gcnew String("Out of range");
		break;
	case NL_STATUS_SIZE:
		return gcnew String("Invalid size");
		break;
	case NL_STATUS_VERSION:
		return gcnew String("Invalid version");
		break;
	case NL_STATUS_WRITE:
		return gcnew String("Write failure");
		break;
	}

	return gcnew String("Unknown error");
}

using namespace System::Runtime::InteropServices;

// Every time you marshall a SecureString to an unmanaged memory, a tree dies.
// But sometimes you have to do it, like you have to interface with native code.
//
// Use wchar_t * to hold the data. No std::strings, because we can't gaurantee that
// the memory can be securely wiped when we are done with them.
LPWSTR PasswordManagerCore::M_SecureString_to_LPWSTR(SecureString ^ss)
{
	IntPtr wsp = IntPtr::Zero;

	if (!ss)
	{
		return NULL;
	}

	wsp = Marshal::SecureStringToGlobalAllocUnicode(ss);
	return (wchar_t *)wsp.ToPointer();
}

void PasswordManagerCore::M_Free_LPWSTR(LPWSTR ws)
{
	Marshal::ZeroFreeGlobalAllocUnicode((IntPtr)ws);
}