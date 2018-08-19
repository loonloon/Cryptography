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

#include <sgx_tseal.h>
#include <stdint.h>
#include <stddef.h>
#include <string>
#include <string.h>
#include <time.h>
#include "E_Vault.h"
#include "E_Pack.h"
#include "PasswordManagerError.h"
#include "Enclave_t.h"

using namespace Pack;

// Header size by E_E_Vault version number (v0 doesn't count).
static const uint16_t header_size[2] = { 0, 86 };

//=========================================================================
// E_Vault
//=========================================================================

E_Vault::E_Vault()
{
	db_data = NULL;
	db_version = 1;
	db_size = 0;
	state = _VST_UPDSIZE;
	naccounts = 0;
	sealsz = 0;
	lock_delay = 0;
}


E_Vault::~E_Vault()
{
	if (db_data != NULL) delete[] db_data;
}

// We are creating a new E_Vault

int E_Vault::initialize()
{
	this->clear();

	// Generate a database key
	crypto_status_t rv = crypto.generate_database_key((unsigned char *)db_key, NULL);

	if (rv == CRYPTO_ERR_USER_CANCEL)
	{
		return NL_STATUS_USER_CANCEL;
	}

	state |= _VST_DBKEY;
	return NL_STATUS_OK;
}

// We are reading an existing E_Vault
int E_Vault::initialize(const unsigned char *header, uint16_t hsize)
{
	this->clear();

	memcpy(m_pw_salt, header, 8);
	memcpy(db_key_nonce, header + 8, 12);
	memcpy(db_key_tag, header + 20, 16);
	memcpy(db_key_enc, header + 36, 16);

	db_version = unpack_uint16((unsigned char *)&header[52]);
	db_size = unpack_uint32((unsigned char *)&header[54]);

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

void E_Vault::clear(void)
{
	if (db_data != NULL)
	{
		delete[] db_data;
	}

	db_data = NULL;
	db_version = 1;
	db_size = 0;
	naccounts = 0;
	state = _VST_UPDSIZE;
	this->clear_account_info();
}

void E_Vault::clear_account_info()
{
	for (uint32_t i = 0; i < MAX_ACCOUNTS; ++i)
	{
		E_AccountRecord *acct = &accounts[i];
		acct->clear();
	}
}

int E_Vault::unlock(const char *password)
{
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (!this->is_locked())
	{
		return NL_STATUS_OK;
	}

	// Validate the passphrase by attempting to decrypt the database key
	crypto_status_t rv = crypto.unlock_vault((unsigned char *)password, (unsigned long)strlen(password), (unsigned char *)m_pw_salt, (unsigned char *)db_key_enc, (unsigned char *)db_key_nonce,
		(unsigned char *)db_key_tag, (unsigned char *)db_key);

	if (rv == CRYPTO_ERR_DECRYPT_AUTH)
	{
		return NL_STATUS_PASSWORD;
	}

	if (rv != NL_STATUS_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	_VST_CLEAR(_VST_LOCKED);
	return NL_STATUS_OK;
}

void E_Vault::lock()
{
	// Can't lock an incomplete/invalid E_Vault
	if (!this->is_valid())
	{
		return;
	}

	_VST_SET(_VST_LOCKED);
}

int E_Vault::load_vault(const unsigned char *edata)
{
	using namespace std;

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

	// Decrypt the E_Vault to our new buffer
	crypto_status_t rv = crypto.decrypt_database((unsigned char *)db_key, (unsigned char *)edata, db_size, (unsigned char *)db_data_nonce, (unsigned char *)db_data_tag, (unsigned char *)db_data);

	if (rv == CRYPTO_ERR_DECRYPT_AUTH)
	{
		return NL_STATUS_PASSWORD;
	}

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	// Parse the data
	char *cp = db_data;
	naccounts = unpack_uint32((unsigned char *)cp);

	if (naccounts >= MAX_ACCOUNTS)
	{
		delete[] db_data;
		return NL_STATUS_BADFILE;
	}

	cp += 4;

	for (uint32_t i = 0; i < naccounts; ++i)
	{
		E_AccountRecord *acct = &accounts[i];

		// Record length
		char *ep = cp;
		uint32_t reclen = unpack_uint32((unsigned char *)cp); cp += 4;
		ep += reclen;

		// Encrypted password
		uint16_t slen = unpack_uint16((unsigned char *)cp); cp += 2;
		acct->set_nonce(cp); cp += 12;
		acct->set_tag(cp); cp += 16;

		if (slen)
		{
			acct->set_enc_pass(cp, slen); cp += slen;
		}

		// Account name
		slen = unpack_uint16((unsigned char *)cp); cp += 2;

		if (slen)
		{
			if (acct->set_name(cp, slen)) cp += slen;
			else goto alloc_error;
		}

		// Login name
		slen = unpack_uint16((unsigned char *)cp); cp += 2;

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
		slen = unpack_uint16((unsigned char *)cp); cp += 2;

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
			delete[] db_data;
			this->clear_account_info();
			return NL_STATUS_BADFILE;
		}
	}

	return NL_STATUS_OK;

alloc_error:
	delete[] db_data;
	this->clear_account_info();
	return NL_STATUS_ALLOC;
}

int E_Vault::get_header(unsigned char *header, uint16_t *size)
{
	unsigned char *cp = header;

	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	// Header size is defined by E_Vault file version number
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

uint32_t E_Vault::get_db_size()
{
	if (_VST_ISSET(_VST_UPDSIZE))
	{
		db_size = 0;

		for (uint32_t i = 0; i < naccounts; ++i)
		{
			// Don't send info for completely blank accounts.
			E_AccountRecord *acct = &accounts[i];
			uint16_t llen, ulen, elen;
			uint16_t nlen = llen = ulen = elen = 0;

			nlen = acct->get_name_len();
			llen = acct->get_login_len();
			ulen = acct->get_url_len();
			elen = acct->get_epass_len();

			if (nlen || llen || ulen || elen)
			{
				db_size += 40 + nlen + llen + ulen + elen; // The strings in the E_Vault are NOT NULL terminated
			}
		}

		db_size += 4; // Entry count
		_VST_CLEAR(_VST_UPDSIZE);
	}

	return db_size;
}

int E_Vault::get_vault(unsigned char *edata, uint32_t *size)
{
	int rv;
	unsigned char nonce[12], tag[16];

	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (edata == NULL)
	{
		*size = this->get_db_size();
		return NL_STATUS_OK;
	}

	unsigned char *data = new unsigned char[*size];

	if (data == NULL)
	{
		return NL_STATUS_ALLOC;
	}

	unsigned char *cp = &data[4]; // Skip record count for now
	uint32_t count = 0;

	for (uint32_t i = 0; i < naccounts; ++i)
	{
		// Don't send info for completely blank accounts.
		E_AccountRecord *acct = &accounts[i];
		uint16_t llen, ulen, elen;
		uint16_t nlen = llen = ulen = elen = 0;

		nlen = acct->get_name_len();
		llen = acct->get_login_len();
		ulen = acct->get_url_len();
		elen = acct->get_epass_len();

		// Get string lengths first. If there are 0 we are an emtpy account record
		uint32_t rsize = (uint32_t)nlen + (uint32_t)llen + (uint32_t)ulen + (uint32_t)elen;

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
	int status = crypto.generate_nonce_gcm((unsigned char *)nonce);

	if (status == CRYPTO_OK)
	{
		status = crypto.encrypt_database((unsigned char *)db_key, data, *size, edata, (unsigned char *)nonce, (unsigned char *)tag, 0);

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

	delete[] data;
	return rv;
}

int E_Vault::set_master_password(const char *password)
{
	char mkey[16];

	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only set the master password if one hasn't been set already
	if (_VST_ISSET(_VST_MPASS))
	{
		return NL_STATUS_INVALID;
	}

	crypto_status_t rv = crypto.generate_salt((unsigned char *)m_pw_salt);

	if (rv == CRYPTO_ERR_DRNG)
	{
		return NL_STATUS_RAND;
	}

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_RAND;
	}

	rv = crypto.derive_master_key((unsigned char *)password, (unsigned long)strlen(password), (unsigned char *)m_pw_salt, (unsigned char *)mkey);

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_RAND;
	}

	rv = crypto.encrypt_database_key((unsigned char *)mkey, (unsigned char *)db_key, (unsigned char *)db_key_enc, (unsigned char *)db_key_nonce, (unsigned char *)db_key_tag, 0);

	if (rv != CRYPTO_OK)
	{
		return NL_STATUS_UNKNOWN;
	}

	_VST_SET(_VST_MPASS);
	return NL_STATUS_OK;
}

int E_Vault::change_master_password(const char *oldpass, const char *newpass)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	crypto_status_t rv = crypto.validate_passphrase((unsigned char *)oldpass, (unsigned long)strlen(oldpass), (unsigned char *)m_pw_salt, (unsigned char *)db_key_enc, (unsigned char *)db_key_nonce,
		(unsigned char *)db_key_tag);

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

int E_Vault::accounts_get_count(uint32_t *count)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	*count = naccounts;
	return NL_STATUS_OK;
}

// Return length of each string.

int E_Vault::accounts_get_info_sizes(uint32_t idx, uint16_t *mbname_sz, uint16_t *mblogin_sz, uint16_t *mburl_sz)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	E_AccountRecord *acct = &accounts[idx];

	// Make room for NULL byte
	*mbname_sz = acct->get_name_len() + 1;
	*mblogin_sz = acct->get_login_len() + 1;
	*mburl_sz = acct->get_url_len() + 1;

	return NL_STATUS_OK;
}

int E_Vault::accounts_get_info(uint32_t idx, char *mbname, uint16_t mbname_sz, char *mblogin, uint16_t mblogin_sz,
	char *mburl, uint16_t mburl_sz)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	E_AccountRecord *acct = &accounts[idx];
	uint16_t mlen = acct->get_name_len();
	uint16_t llen = acct->get_login_len();
	uint16_t ulen = acct->get_url_len();

	// Need enough room for the NULL byte
	if (mbname_sz <= mlen || mblogin_sz <= llen || mburl_sz <= ulen)
	{
		return NL_STATUS_SIZE;
	}

	strncpy(mbname, acct->get_name(), mlen + 1);
	strncpy(mblogin, acct->get_login(), llen + 1);
	strncpy(mburl, acct->get_url(), ulen + 1);

	return NL_STATUS_OK;
}

int E_Vault::accounts_get_password_size(uint32_t idx, uint16_t *sz)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	E_AccountRecord *acct = &accounts[idx];
	*sz = acct->get_epass_len() + 1; // Need room for NULL byte

	return NL_STATUS_OK;
}

int E_Vault::accounts_get_password(uint32_t idx, char *mbpass, uint16_t sz)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	E_AccountRecord *acct = &accounts[idx];
	uint16_t pwlen = (uint16_t)acct->get_epass_len();

	// Need enough room for the NULL byte
	if (sz <= pwlen)
	{
		return NL_STATUS_SIZE;
	}

	if (pwlen > 0)
	{
		// But don't include that extra unsigned char here
		crypto_status_t rv = crypto.decrypt_account_password((unsigned char *)db_key, (unsigned char *)acct->get_epass(), pwlen, (unsigned char *)acct->get_nonce(), (unsigned char *)acct->get_tag(), (unsigned char *)mbpass);

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
	mbpass[pwlen] = NULL;
	return NL_STATUS_OK;
}

int E_Vault::accounts_set_info(uint32_t idx, const char *mbname, uint16_t mbname_len, const char *mblogin, uint16_t mblogin_len,
	const char *mburl, uint16_t mburl_len)
{
	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	E_AccountRecord *acct = &accounts[idx];

	if (mbname_len == USHRT_MAX || mblogin_len == USHRT_MAX || mburl_len == USHRT_MAX)
	{
		return NL_STATUS_SIZE;
	}

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

int E_Vault::accounts_set_password(uint32_t idx, const char *mbpass, uint16_t mbpass_len)
{
	char nonce[12], tag[16];

	// Can't do this to a locked E_Vault
	if (this->is_locked())
	{
		return NL_STATUS_PERM;
	}

	// Can only do this on a valid/complete E_Vault
	if (!this->is_valid())
	{
		return NL_STATUS_INVALID;
	}

	if (idx >= MAX_ACCOUNTS)
	{
		return NL_STATUS_RANGE;
	}

	if (mbpass_len == USHRT_MAX)
	{
		return NL_STATUS_SIZE;
	}

	char *epass = new char[mbpass_len]; // We don't need the NULL unsigned char
	E_AccountRecord *acct = &accounts[idx];

	if (mbpass_len)
	{
		crypto_status_t rv = crypto.generate_nonce_gcm((unsigned char *)nonce);

		if (rv != CRYPTO_OK)
		{
			return NL_STATUS_RAND;
		}

		// But don't include the unsigned char here.
		rv = crypto.encrypt_account_password((unsigned char *)db_key, (unsigned char *)mbpass, mbpass_len, (unsigned char *)epass, (unsigned char *)nonce, (unsigned char *)tag);

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

		if (idx > naccounts) naccounts = idx + 1;
	}
	else
	{
		return NL_STATUS_ALLOC;
	}

	_VST_SET(_VST_UPDSIZE);
	return NL_STATUS_OK;
}

int E_Vault::accounts_generate_password(uint16_t length, uint16_t pwflags, char *buffer)
{
	return crypto.generate_password((unsigned char *)buffer, length, pwflags);
}

uint32_t E_Vault::get_state_size()
{
	if (sealsz)
	{
		return sealsz;
	}

	sealsz = sgx_calc_sealed_data_size(0, sizeof(vault_state_t));
	return sealsz;
}

int E_Vault::heartbeat(char *state_data, uint32_t sz)
{
	vault_state_t vault_state;
	uint64_t ts;
	static sgx_attributes_t attr = { (SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG /*| SGX_FLAGS_LICENSE_KEY*/)&(~(SGX_FLAGS_RESERVED)), 0 };
	static sgx_misc_select_t misc = 0;

	// Copy the db key
	memcpy(vault_state.db_key, db_key, 16);

	// To get the system time and PID we need to make an OCALL
	sgx_status_t status = ve_o_process_info(&ts, &vault_state.pid);

	if (status != SGX_SUCCESS)
	{
		return NL_STATUS_SGXERROR;
	}

	vault_state.lastheartbeat = (sgx_time_t)ts;

	// Storing both the start and end times provides some 
	// protection against clock manipulation. It's not perfect,
	// but it's better than nothing.
	vault_state.lockafter = vault_state.lastheartbeat + lock_delay;

	// Saves us an ECALL to have to reset this when the vault is restored.
	vault_state.lock_delay = lock_delay;

	// Seal our data with the MRENCLAVE policy. We defined our
	// struct as packed to support working on the address
	// directly like this.	
	status = sgx_seal_data_ex(SGX_KEYPOLICY_MRENCLAVE, attr, misc, 0, NULL, sizeof(vault_state_t), (uint8_t *)&vault_state, sz, (sgx_sealed_data_t *)state_data);

	if (status != SGX_SUCCESS)
	{
		return NL_STATUS_SGXERROR;
	}

	return NL_STATUS_OK;
}

// Restore the vault DB password from the sealed data file if
// we have not reached the lock timeout, the PIDs match, and
// no other errors occur.
//
// No matter what happens, zero out the state data that was
// passed in (you only get one try). Also, return NL_STATUS_PERM
// on a failure, no matter the failure.
int E_Vault::restore_state(char *state_data, uint32_t sz)
{
	vault_state_t vault_state;
	uint64_t now, thispid;
	uint32_t szout = sz;

	// First, make an OCALL to get the current process ID and system time.
	// Make these OCALLs so that the parameters aren't be supplied by the
	// ECALL (which would make it trivial for the calling process to fake 
	// this information)
	sgx_status_t status = ve_o_process_info(&now, &thispid);

	if (status != SGX_SUCCESS)
	{
		// Zap the state data.
		memset_s(state_data, sz, 0, sz);
		return NL_STATUS_SGXERROR;
	}

	status = sgx_unseal_data((sgx_sealed_data_t *)state_data, NULL, 0, (uint8_t *)&vault_state, &szout);

	// Zap the state data.
	memset_s(state_data, sz, 0, sz);

	if (status != SGX_SUCCESS)
	{
		return NL_STATUS_SGXERROR;
	}

	if (thispid != vault_state.pid)
	{
		return NL_STATUS_PERM;
	}

	if (now < vault_state.lastheartbeat)
	{
		return NL_STATUS_PERM;
	}

	if (now > vault_state.lockafter)
	{
		return NL_STATUS_PERM;
	}

	// Everything checks out. Restore the key and mark the vault as unlocked.
	lock_delay = vault_state.lock_delay;
	memcpy(db_key, vault_state.db_key, 16);
	_VST_CLEAR(_VST_LOCKED);

	return NL_STATUS_OK;
}

//=========================================================================
// Account Record
//=========================================================================
E_AccountRecord::E_AccountRecord()
{
	memset_s(nonce, 12, 0, 12);
	memset_s(tag, 16, 0, 16);
}

E_AccountRecord::~E_AccountRecord()
{
}

void E_AccountRecord::clear()
{
	memset_s(nonce, 12, 0, 12);
	memset_s(tag, 16, 0, 16);
	name.clear();
	epass.clear();
	url.clear();
	login.clear();
}
