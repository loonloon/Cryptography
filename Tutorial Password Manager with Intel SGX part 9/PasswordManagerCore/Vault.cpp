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
#include <string.h>
#include <time.h>
#include <NCrypt.h>
#include <NCryptprotect.h>
#include "Vault.h"
#include "Pack.h"
#include "PasswordManagerError.h"

#pragma unmanaged

// Header size by vault version number (v0 doesn't count).
static const UINT16 header_size[2] = { 0, 86 };

using namespace Pack;

//=========================================================================
// Vault
//=========================================================================
Vault::Vault()
{
	db_data = NULL;
	db_version = 1;
	db_size = 0;
	state = _VST_UPDSIZE;
	naccounts = 0;
	crypto.generate_salt_ex((PBYTE)db_key_xor, 16);
	db_key_prot = NULL;
	flag_dpapi = (NCryptCreateProtectionDescriptor(L"LOCAL=user", 0, &h_db_key) == ERROR_SUCCESS) ? 1 : 0;
}

Vault::~Vault()
{
	SecureZeroMemory(db_key_xor, 16);
	SecureZeroMemory(db_key_obs, 16);

	if (db_key_prot != NULL)
	{
		LocalFree(db_key_prot);
	}

	if (db_data != NULL)
	{
		delete[] db_data;
	}
}

void Vault::set_db_key(const char db_key[16])
{
	UINT i, j;

	// Use DPAPI to store the database password in an encrpyted form, unless something
	// tragic happens.
	if (flag_dpapi)
	{
		if (db_key_prot != NULL)
		{
			LocalFree(db_key_prot);
		}

		if (NCryptProtectSecret(h_db_key, NCRYPT_SILENT_FLAG, (const PBYTE)db_key, 16, NULL, NULL, &db_key_prot, &db_key_prot_sz) == ERROR_SUCCESS)
		{
			return;
		}

		db_key_prot = NULL;
	}

	// DPAPI failed? Use a simple XOR to encode the key just so it isn't sitting decrypted 
	// in memory. Yes, it's security through obscurity, but it's marginally better than 
	// leaving it wide open.
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			db_key_obs[4 * i + j] = db_key[4 * i + j] ^ db_key_xor[4 * i + j];
		}
	}
}

void Vault::get_db_key(char db_key[16])
{
	UINT i, j;

	if (flag_dpapi && db_key_prot != NULL)
	{
		PBYTE buffer;
		ULONG bsize;

		// This doesn't really act on failures, which is bad.
		// It should be fixed. And get_db_key would need to
		// be changed to return an int instead of void.
		//
		// But, we shouldn't worry because this should never
		// fail, right? ... Right? ... um, hello?
		if (NCryptUnprotectSecret(NULL, NCRYPT_SILENT_FLAG, db_key_prot, db_key_prot_sz, NULL, NULL, &buffer, &bsize) == ERROR_SUCCESS)
		{
			if (bsize == 16)
			{
				memcpy(db_key, buffer, 16);
			}

			SecureZeroMemory(buffer, bsize);
			LocalFree(buffer);
		}

		return;
	}

	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			db_key[4 * i + j] = db_key_obs[4 * i + j] ^ db_key_xor[4 * i + j];
		}
	}
}

// We are creating a new vault
int Vault::initialize()
{
	crypto_status_t rv;
	char db_key[16];
	this->clear();

	// Generate a database key
	rv = crypto.generate_database_key((PBYTE)db_key, NULL);

	if (rv == CRYPTO_ERR_USER_CANCEL)
	{
		SecureZeroMemory(db_key, 16);
		return NL_STATUS_USER_CANCEL;
	}

	set_db_key(db_key);
	SecureZeroMemory(db_key, 16);
	state |= _VST_DBKEY;

	return NL_STATUS_OK;
}

// We are reading an existing vault
int Vault::initialize(const unsigned char *header, UINT16 hsize)
{
	this->clear();

	memcpy(m_pw_salt, header, 8);
	memcpy(db_key_nonce, header + 8, 12);
	memcpy(db_key_tag, header + 20, 16);
	memcpy(db_key_enc, header + 36, 16);

	db_version = unpack_uint16((PBYTE)&header[52]);
	db_size = unpack_uint32((PBYTE)&header[54]);

	memcpy(db_data_nonce, header + 58, 12);
	memcpy(db_data_tag, header + 70, 16);

	// Only one database version supported so far
	if (db_version != 1)
	{
		this->clear();
		return NL_STATUS_VERSION;
	}

	if (hsize != header_size[db_version])
	{
		this->clear();
		return NL_STATUS_INVALID;
	}

	state = _VST_VALID_BITS | _VST_LOCKED;
	return NL_STATUS_OK;
}

void Vault::clear(void)
{
	if (db_data != NULL)
	{
		delete[] db_data;
	}

	db_data = NULL;
	db_version = 1;
	db_size = 0;
	state = _VST_UPDSIZE;
	this->clear_account_info();
}

void Vault::clear_account_info()
{
	UINT32 i;

	for (i = 0; i < MAX_ACCOUNTS; ++i)
	{
		AccountRecord *acct = &accounts[i];
		acct->clear();
	}
}

int Vault::unlock(const char *password)
{
	crypto_status_t rv;
	char db_key[16];

	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (!this->is_locked())
	{
		return NL_STATUS_OK;
	}

	// Validate the passphrase by attempting to decrypt the database key
	rv = crypto.unlock_vault((PBYTE)password, (ULONG)strlen(password), (PBYTE)m_pw_salt, (PBYTE)db_key_enc, (PBYTE)db_key_nonce,
		(PBYTE)db_key_tag, (PBYTE)db_key);

	if (rv == CRYPTO_ERR_DECRYPT_AUTH)
	{
		return NL_STATUS_PASSWORD;
	}
	else if (rv != NL_STATUS_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	_VST_CLEAR(_VST_LOCKED);
	set_db_key(db_key);
	SecureZeroMemory(db_key, 16);

	return NL_STATUS_OK;
}

void Vault::lock()
{
	// Can't lock an incomplete/invalid vault
	if (!this->is_valid())
	{
		return;
	}

	SecureZeroMemory(db_key_obs, 16);
	_VST_SET(_VST_LOCKED);
}

int Vault::load_vault(const unsigned char *edata)
{
	using namespace std;
	crypto_status_t rv;
	char *cp;
	UINT32 i;
	char db_key[16];

	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (db_data != NULL)
	{
		delete[] db_data;
	}

	db_data = new char[db_size];

	// Decrypt the vault to our new buffer
	get_db_key(db_key);
	rv = crypto.decrypt_database((PBYTE)db_key, (PBYTE)edata, db_size, (PBYTE)db_data_nonce, (PBYTE)db_data_tag, (PBYTE)db_data);
	SecureZeroMemory(db_key, 16);

	if (rv == CRYPTO_ERR_DECRYPT_AUTH)
	{
		return NL_STATUS_PASSWORD;
	}

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	// Parse the data
	cp = db_data;
	naccounts = unpack_uint32((PBYTE)cp);

	if (naccounts >= MAX_ACCOUNTS)
	{
		SecureZeroMemory(db_data, db_size);
		delete[] db_data;
		return NL_STATUS_BADFILE;
	}

	cp += 4;

	for (i = 0; i < naccounts; ++i)
	{
		AccountRecord *acct = &accounts[i];
		char *ep;
		UINT32 reclen;
		UINT16 slen;

		// Record length
		ep = cp;
		reclen = unpack_uint32((PBYTE)cp); cp += 4;
		ep += reclen;

		// Encrypted password
		slen = unpack_uint16((PBYTE)cp); cp += 2;
		acct->set_nonce(cp); cp += 12;
		acct->set_tag(cp); cp += 16;

		if (slen)
		{
			acct->set_enc_pass(cp, slen); cp += slen;
		}

		// Account name
		slen = unpack_uint16((PBYTE)cp); cp += 2;

		if (slen)
		{
			if (acct->set_name(cp, slen))
			{
				cp += slen;
			}
			else
			{
				goto alloc_error;
			}
		}

		// Login name
		slen = unpack_uint16((PBYTE)cp); cp += 2;

		if (slen)
		{
			if (acct->set_login(cp, slen))
			{
				cp += slen;
			}
			else
			{
				goto alloc_error;
			}
		}

		// URL name
		slen = unpack_uint16((PBYTE)cp); cp += 2;

		if (slen)
		{
			if (acct->set_url(cp, slen))
			{
				cp += slen;
			}
			else
			{
				goto alloc_error;
			}
		}

		if (cp != ep)
		{
			SecureZeroMemory(db_data, db_size);
			delete[] db_data;
			this->clear_account_info();
			return NL_STATUS_BADFILE;
		}
	}

	return NL_STATUS_OK;

alloc_error:
	SecureZeroMemory(db_data, db_size);
	delete[] db_data;
	this->clear_account_info();
	return NL_STATUS_ALLOC;
}

int Vault::get_header(unsigned char *header, UINT16 *size)
{
	unsigned char *cp = header;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	// Header size is defined by vault file version number
	if (db_version == 0 || db_version > MAX_VAULT_VERSION)
	{
		db_version = MAX_VAULT_VERSION;
	}

	if (header == NULL)
	{
		*size = header_size[db_version];
		return NL_STATUS_OK;
	}

	if (*size < header_size[db_version])
	{
		return NL_STATUS_SIZE;
	}

	// Get our DB size
	db_size = this->get_db_size();

	// Write our new header to the specified buffer
	memcpy(cp, m_pw_salt, 8); cp += 8;
	memcpy(cp, db_key_nonce, 12); cp += 12;
	memcpy(cp, db_key_tag, 16); cp += 16;
	memcpy(cp, db_key_enc, 16); cp += 16;
	pack_uint16(cp, db_version); cp += 2;
	pack_uint32(cp, db_size); cp += 4;
	memcpy(cp, db_data_nonce, 12); cp += 12;
	memcpy(cp, db_data_tag, 16);

	return NL_STATUS_OK;
}

UINT32 Vault::get_db_size()
{
	if (_VST_ISSET(_VST_UPDSIZE))
	{
		UINT32 i;
		db_size = 0;

		for (i = 0; i < naccounts; ++i)
		{
			// Don't send info for completely blank accounts. Note that we'll update naccounts
			// afterwards, to compact the vault by removing any blanks in between other
			// accounts.
			AccountRecord *acct = &accounts[i];
			UINT16 nlen, llen, ulen, elen;

			nlen = llen = ulen = elen = 0;

			nlen = acct->get_name_len();
			llen = acct->get_login_len();
			ulen = acct->get_url_len();
			elen = acct->get_epass_len();

			if (nlen || llen || ulen || elen)
			{
				db_size += 40 + nlen + llen + ulen + elen; // The strings in the vault are NOT NULL terminated
			}
		}

		db_size += 4; // Entry count
		_VST_CLEAR(_VST_UPDSIZE);
	}

	return db_size;
}

int Vault::get_vault(unsigned char *edata, UINT32 *size)
{
	unsigned char *cp, *data;
	UINT32 i, count;
	int status, rv;
	unsigned char nonce[12], tag[16];

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (edata == NULL)
	{
		*size = this->get_db_size();
		return NL_STATUS_OK;
	}

	data = new unsigned char[*size];

	if (data == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	cp = &data[4]; // Skip record count for now
	count = 0;

	for (i = 0; i < naccounts; ++i)
	{
		// Don't send info for completely blank accounts. Note that we'll update naccounts
		// afterwards, to compact the vault by removing any blanks in between other
		// accounts.
		AccountRecord *acct = &accounts[i];
		UINT16 nlen, llen, ulen, elen;
		UINT32 rsize;

		nlen = llen = ulen = elen = 0;

		nlen = acct->get_name_len();
		llen = acct->get_login_len();
		ulen = acct->get_url_len();
		elen = acct->get_epass_len();

		// Get string lengths first. If there are 0 we are an emtpy account record
		rsize = (UINT32)nlen + (UINT32)llen + (UINT32)ulen + (UINT32)elen;

		if (rsize)
		{
			// Add the other fields
			rsize += 40;
			++count;

			// And pack
			pack_uint32(cp, rsize); cp += 4;
			pack_uint16(cp, elen); cp += 2;
			memcpy(cp, acct->get_nonce(), 12); cp += 12;
			memcpy(cp, acct->get_tag(), 16); cp += 16;
			memcpy(cp, acct->get_epass(), elen); cp += elen;
			pack_uint16(cp, nlen); cp += 2;
			memcpy(cp, acct->get_name(), nlen); cp += nlen;
			pack_uint16(cp, llen); cp += 2;
			memcpy(cp, acct->get_login(), llen); cp += llen;
			pack_uint16(cp, ulen); cp += 2;
			memcpy(cp, acct->get_url(), ulen); cp += ulen;
		}
	}

	// Now pack the entry count
	pack_uint32(data, count);

	// Now encrypt to the specified buffer. We need a new nonce.
	status = crypto.generate_nonce_gcm((PBYTE)nonce);

	if (status == CRYPTO_OK)
	{
		char db_key[16];
		get_db_key(db_key);
		status = crypto.encrypt_database((PBYTE)db_key, data, *size, edata, (PBYTE)nonce, (PBYTE)tag, 0);
		SecureZeroMemory(db_key, 16);

		if (status == CRYPTO_OK)
		{
			memcpy(db_data_nonce, nonce, 12);
			memcpy(db_data_tag, tag, 16);
			rv = NL_STATUS_OK;
		}
		else
		{
			rv = NL_STATUS_UNKNOWN;
		}
	}
	else
	{
		rv = NL_STATUS_RAND;
	}

	SecureZeroMemory(data, *size);
	delete[] data;
	return rv;
}

int Vault::set_master_password(const char *password)
{
	char mkey[16];
	crypto_status_t rv;
	char db_key[16];

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only set the master password if one hasn't been set already
	if (_VST_ISSET(_VST_MPASS))
	{
		return NL_STATUS_INVALID;
	}

	rv = crypto.generate_salt((PBYTE)m_pw_salt);

	if (rv == CRYPTO_ERR_DRNG)
	{
		return NL_STATUS_RAND;
	}

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_RAND;
	}

	rv = crypto.derive_master_key((PBYTE)password, (ULONG)strlen(password), (PBYTE)m_pw_salt, (PBYTE)mkey);

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_RAND;
	}

	get_db_key(db_key);
	rv = crypto.encrypt_database_key((PBYTE)mkey, (PBYTE)db_key, (PBYTE)db_key_enc, (PBYTE)db_key_nonce, (PBYTE)db_key_tag, 0);
	SecureZeroMemory(db_key, 16);

	// Zero this no matter what the result was
	SecureZeroMemory(mkey, 16);

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	_VST_SET(_VST_MPASS);
	return NL_STATUS_OK;
}

int Vault::change_master_password(const char *oldpass, const char *newpass)
{
	crypto_status_t rv;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	rv = crypto.validate_passphrase((PBYTE)oldpass, (ULONG)strlen(oldpass), (PBYTE)m_pw_salt, (PBYTE)db_key_enc, (PBYTE)db_key_nonce,
		(PBYTE)db_key_tag);

	if (rv == CRYPTO_ERR_PASS_MISMATCH)
	{
		return NL_STATUS_PASSWORD;
	}

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	// So that we can call set_master_password()
	_VST_CLEAR(_VST_MPASS);
	return this->set_master_password(newpass);
}

int Vault::accounts_get_count(UINT32 *count)
{
	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	*count = naccounts;
	return NL_STATUS_OK;
}

int Vault::accounts_get_info_sizes(UINT32 idx, UINT16 *mbname_sz, UINT16 *mblogin_sz, UINT16 *mburl_sz)
{
	AccountRecord *acct;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	acct = &accounts[idx];

	*mbname_sz = acct->get_name_len() + 1;
	*mblogin_sz = acct->get_login_len() + 1;
	*mburl_sz = acct->get_url_len() + 1;

	return NL_STATUS_OK;
}

int Vault::accounts_get_info(UINT32 idx, char *mbname, UINT16 mbname_sz, char *mblogin, UINT16 mblogin_sz,
	char *mburl, UINT16 mburl_sz)
{
	AccountRecord *acct;
	UINT16 nlen, llen, ulen;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	acct = &accounts[idx];
	nlen = acct->get_name_len();
	llen = acct->get_login_len();
	ulen = acct->get_url_len();

	if (mbname_sz <= nlen || mblogin_sz <= llen || mburl_sz <= ulen)
	{
		return NL_STATUS_SIZE;
	}

	if (mbname != NULL)
	{
		strncpy(mbname, acct->get_name(), nlen + 1);
	}

	if (mblogin != NULL)
	{
		strncpy(mblogin, acct->get_login(), llen + 1);
	}

	if (mburl != NULL)
	{
		strncpy(mburl, acct->get_url(), ulen + 1);
	}

	return NL_STATUS_OK;
}

int Vault::accounts_get_password_size(UINT32 idx, UINT16 *sz)
{
	AccountRecord *acct;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	acct = &accounts[idx];
	*sz = (UINT16)acct->get_epass_len() + 1;
	return NL_STATUS_OK;
}

int Vault::accounts_get_password(UINT32 idx, char *mbpass, UINT16 sz)
{
	AccountRecord *acct;
	crypto_status_t rv;
	char db_key[16];
	UINT16 len;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	acct = &accounts[idx];
	len = (UINT16)acct->get_epass_len();

	if (sz <= len)
	{
		return NL_STATUS_SIZE;
	}

	if (len > 0)
	{
		// But don't include that extra byte here
		get_db_key(db_key);
		rv = crypto.decrypt_account_password((PBYTE)db_key, (PBYTE)acct->get_epass(), len, (PBYTE)acct->get_nonce(), (PBYTE)acct->get_tag(), (PBYTE)mbpass);
		SecureZeroMemory(db_key, 16);

		if (rv != CRYPTO_OK)
		{
			if (rv = CRYPTO_ERR_DECRYPT_AUTH)
			{
				return NL_STATUS_PASSWORD;
			}

			return NL_STATUS_UNKNOWN;
		}
	}

	// NULL terminate
	mbpass[len] = 0;
	return NL_STATUS_OK;
}

int Vault::accounts_set_info(UINT32 idx, const char *mbname, UINT16 mbname_len, const char *mblogin, UINT16 mblogin_len,
	const char *mburl, UINT16 mburl_len)
{
	AccountRecord *acct;

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	acct = &accounts[idx];

	if (acct->set_name(mbname, mbname_len) && acct->set_login(mblogin, mblogin_len) &&
		acct->set_url(mburl, mburl_len))
	{

		_VST_SET(_VST_UPDSIZE);

		if (idx > naccounts)
		{
			naccounts = idx + 1;
		}
		return NL_STATUS_OK;
	}

	return NL_STATUS_ALLOC;
}

int Vault::accounts_set_password(UINT32 idx, const char *mbpass, UINT16 mbpass_len)
{
	AccountRecord *acct;
	crypto_status_t rv;
	char *epass;
	char nonce[12], tag[16];

	// Can't do this to a locked vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	epass = new char[mbpass_len]; // We don't need the NULL byte
	acct = &accounts[idx];
	SecureZeroMemory(nonce, 12);
	SecureZeroMemory(tag, 16);

	if (mbpass_len)
	{
		char db_key[16];
		rv = crypto.generate_nonce_gcm((PBYTE)nonce);

		if (rv != CRYPTO_OK)
		{
			return NL_STATUS_RAND;
		}

		// But don't include the byte here.
		get_db_key(db_key);
		rv = crypto.encrypt_account_password((PBYTE)db_key, (PBYTE)mbpass, mbpass_len, (PBYTE)epass, (PBYTE)nonce, (PBYTE)tag);
		SecureZeroMemory(db_key, 16);

		if (rv != CRYPTO_OK)
		{
			return NL_STATUS_UNKNOWN;
		}
	}

	if (acct->set_enc_pass(epass, mbpass_len))
	{
		// This is the one that can fail since it has to alloc memory
		acct->set_nonce(nonce); // Just memcopies
		acct->set_tag(tag);

		if (idx > naccounts)
		{
			naccounts = idx + 1;
		}
	}
	else
	{
		return NL_STATUS_ALLOC;
	}

	_VST_SET(_VST_UPDSIZE);
	return NL_STATUS_OK;
}

int Vault::accounts_generate_password(UINT16 length, UINT16 pwflags, char *buffer)
{
	return crypto.generate_password((PBYTE)buffer, length, pwflags);
}

// For the heartbeat, grab the current time and the process id. Encrypt them
// using the database key so they can't be easily manipulated.
int Vault::heartbeat(char *state_data)
{
	vault_state_t state;
	char db_key[16];
	char state_data_pt[sizeof(state.pid) + sizeof(state.lastheartbeat)];
	char *bp = state_data_pt;
	crypto_status_t status;

	RtlSecureZeroMemory(state_data_pt, sizeof(state_data_pt));

	// We'll appropriate the vault crypto functions to do this.
	if (crypto.generate_nonce_gcm((PBYTE)state.iv) != CRYPTO_OK)
	{
		return 0;
	}

	time(&state.lastheartbeat);
	memcpy(bp, &state.lastheartbeat, sizeof(state.lastheartbeat));
	bp += sizeof(state.lastheartbeat);

	state.pid = GetCurrentProcessId();
	memcpy(bp, &state.pid, sizeof(state.pid));

	// Encrypt the time and pid using the DB key.
	get_db_key(db_key);
	status = crypto.encrypt_database((PBYTE)db_key, (PBYTE)state_data_pt, sizeof(state_data_pt),
		(PBYTE)state_data, (PBYTE)state.iv, (PBYTE)&state.tag, 0);
	SecureZeroMemory(db_key, 16);

	if (status != CRYPTO_OK)
	{
		return 0;
	}

	// Now copy the IV and the auth tag to the state data buffer.
	bp = &state_data[sizeof(state_data_pt)];
	memcpy(bp, state.iv, 12);
	bp += 12;
	memcpy(bp, state.tag, 16);

	return 1;
}

int Vault::check_state(char *state_data, UINT32 state_size)
{
	vault_state_t state;
	char db_key[16];
	char state_data_pt[sizeof(state.pid) + sizeof(state.lastheartbeat)];
	char *bp = &state_data[state_size];
	crypto_status_t status;
	time_t now;
	DWORD thispid;

	time(&now);
	thispid = GetCurrentProcessId();

	// Decrypt the state data. If our time has expired, then we're locked.
	get_db_key(db_key);
	status = crypto.decrypt_database((PBYTE)db_key, (PBYTE)state_data, sizeof(state_data_pt),
		(PBYTE)state_data_pt, (PBYTE)bp, (PBYTE)bp + 16);
	SecureZeroMemory(db_key, 16);

	if (status != CRYPTO_OK)
	{
		return NL_STATUS_PERM;
	}

	bp = state_data_pt;
	memcpy(&state.lastheartbeat, bp, sizeof(state.lastheartbeat));
	bp += sizeof(state.lastheartbeat);
	memcpy(&state.pid, bp, sizeof(state.pid));

	if (state.pid != thispid)
	{
		return NL_STATUS_PERM;
	}

	if (now < state.lastheartbeat)
	{
		return NL_STATUS_PERM;
	}

	if (now > (state.lastheartbeat + lock_delay))
	{
		return NL_STATUS_PERM;
	}

	return NL_STATUS_OK;
}

//=========================================================================
// Account Record
//=========================================================================
AccountRecord::AccountRecord()
{
	name = login = url = epass = NULL;
	epass_len = 0;
	SecureZeroMemory(nonce, 12);
	SecureZeroMemory(tag, 16);
}

AccountRecord::~AccountRecord()
{
}

int AccountRecord::set_field(char **field, const char *in, UINT16 len)
{
	char *newfield;
	newfield = new char[len + 1];

	if (newfield == NULL)
	{
		return 0;
	}

	if (len) memcpy(newfield, in, len);
	{
		// we aren't always updating from NULL-terminated strings
	}

	newfield[len] = '\0'; // NULL terminate

	if (*field != NULL)
	{
		this->zero_free_field(*field, (UINT16)strlen(*field));
	}

	*field = newfield;
	return 1;
}

void AccountRecord::clear()
{
	zero_free_field(name, get_name_len());
	zero_free_field(url, get_url_len());
	zero_free_field(login, get_login_len());
	zero_free_field(epass, get_epass_len());
	name = login = url = epass = NULL;
	epass_len = 0;
	SecureZeroMemory(nonce, 12);
	SecureZeroMemory(tag, 16);
}

void AccountRecord::zero_free_field(char *field, UINT16 len)
{
	if (field != NULL)
	{
		SecureZeroMemory(field, len);
	}

	delete[] field;
}

// This is a special case because the field is not NULL-terminated. Danger! Danger!
int AccountRecord::set_enc_pass(const char *in, UINT16 len)
{
	char *newfield;
	newfield = new char[len];

	if (newfield == NULL)
	{
		return 0;
	}

	if (len)
	{
		memcpy(newfield, in, len);
	}

	if (epass != NULL)
	{
		this->zero_free_field(epass, epass_len);
	}

	epass = newfield;
	epass_len = len;
	return 1;
}