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

#pragma comment(lib, "bcrypt")

#include "stdafx.h"
#include "Crypto.h"
#include "common.h"
//----------------------------------------------------------
// This seems to be the standard solution for preventing
// spurious "macro redefinition" warnings when you have
// to include both windows.h and ntstatus.h
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
//----------------------------------------------------------
#include <winnt.h>
#include <string.h>
#include <intrin.h>

#pragma unmanaged

Crypto::Crypto(void)
{
}


Crypto::~Crypto(void)
{
}

crypto_status_t Crypto::generate_database_key(BYTE key_out[16], GenerateDatabaseKeyCallback callback)
{
	ULONG count = 0;

	while ((count = drng.get_seed_bytes(&key_out[count], 16)) < 16)
	{
		if (callback != NULL)
		{
			int rv;

			// So that the GUI can show a progress indicator, a cancel button, etc.
			rv = callback(count, 16);

			if (rv == 0)
			{
				// A zero return value from the callback means we should abort.
				return CRYPTO_ERR_USER_CANCEL;
			}
		}
	}

	if (callback != NULL)
	{
		callback(16, 16);
	}

	return CRYPTO_OK;
}

crypto_status_t Crypto::derive_master_key(PBYTE passphrase, DWORD passphrase_len, BYTE salt[8], BYTE key_out[16])
{
	return this->derive_master_key_ex(passphrase, passphrase_len, (PBYTE)salt, 8, CRYPTO_KDF_ITERATIONS, key_out);
}

crypto_status_t Crypto::derive_master_key_ex(PBYTE passphrase, DWORD passphrase_len, PBYTE salt, DWORD salt_len, ULONG iterations, BYTE key_out[16])
{
	PBYTE messages[3] = { passphrase, salt, NULL };
	DWORD lengths[3] = { passphrase_len, salt_len, 0 };
	BYTE msg[32], md[32], key[32];
	crypto_status_t rv = this->sha256_multi(messages, lengths, md);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	memcpy(key, md, 32);
	messages[1] = msg;
	lengths[1] = 32;

	for (ULONG i = 0; i < iterations; ++i)
	{
		memcpy(msg, md, 32);
		rv = this->sha256_multi(messages, lengths, md);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}

		// The compiler will optimize this
		for (int j = 0; j < 32; ++j)
		{
			key[j] ^= md[j];
		}
	}

	SecureZeroMemory(msg, 32);
	SecureZeroMemory(md, 32);
	memcpy(key_out, &(key[16]), 16);
	SecureZeroMemory(key, 32);

	return CRYPTO_OK;
}

crypto_status_t Crypto::unlock_vault(PBYTE passphrase, ULONG passphrase_len, BYTE salt[8], BYTE db_key_ct[16], BYTE db_key_iv[12], BYTE db_key_tag[16], BYTE db_key_pt[16])
{
	BYTE mkey[16];
	crypto_status_t rv = this->derive_master_key(passphrase, passphrase_len, salt, mkey);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	rv = this->decrypt_database_key(mkey, db_key_ct, db_key_iv, db_key_tag, db_key_pt);
	SecureZeroMemory(mkey, 16);
	return rv;
}

crypto_status_t Crypto::validate_passphrase(PBYTE passphrase, ULONG passphrase_len, BYTE salt[8], BYTE db_key_ct[16], BYTE db_iv[12], BYTE db_tag[16])
{
	return this->validate_passphrase_ex(passphrase, passphrase_len, salt, 8, CRYPTO_KDF_ITERATIONS, db_key_ct, db_iv, db_tag);
}

crypto_status_t Crypto::validate_passphrase_ex(PBYTE passphrase, ULONG passphrase_len, BYTE salt[8], ULONG salt_len, ULONG iterations, BYTE db_key_ct[16], BYTE db_iv[12], BYTE db_tag[16])
{
	BYTE db_key_pt[16]; // We discard this because we don't need it for this routine
	crypto_status_t rv = this->unlock_vault(passphrase, passphrase_len, salt, db_key_ct, db_iv, db_tag, db_key_pt);
	SecureZeroMemory(db_key_pt, 16);
	return rv;
}

crypto_status_t Crypto::generate_salt(BYTE salt[8])
{
	return this->generate_salt_ex(salt, CRYPTO_KDF_SALT_LEN);
}

crypto_status_t Crypto::generate_salt_ex(BYTE *salt, ULONG salt_len)
{
	ULONG n = drng.get_rand_bytes(salt, salt_len);

	if (n != salt_len)
	{
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t Crypto::generate_nonce_gcm(BYTE *nonce)
{
	ULONG n = drng.get_rand_bytes(nonce, 12);

	if (n != 12)
	{
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t Crypto::encrypt_database_key(BYTE master_key[16], BYTE db_key_pt[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[16], DWORD flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(master_key, iv, 12, db_key_pt, 16, db_key_ct, 16, tag, 16);
}

crypto_status_t Crypto::decrypt_database_key(BYTE master_key[16], BYTE db_key_ct[16], BYTE iv[12], BYTE tag[16], BYTE db_key_pt[16])
{
	return this->aes_128_gcm_decrypt(master_key, iv, 12, db_key_ct, 16, db_key_pt, 16, tag, 16);
}

crypto_status_t Crypto::encrypt_account_password(BYTE db_key[16], PBYTE password_pt, ULONG password_len, PBYTE password_ct, BYTE iv[12], BYTE tag[16], DWORD flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, password_pt, password_len, password_ct, password_len, tag, 16);
}

crypto_status_t Crypto::decrypt_account_password(BYTE db_key[16], PBYTE password_ct, ULONG password_len, BYTE iv[12], BYTE tag[16], PBYTE password)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, password_ct, password_len, password, password_len, tag, 16);
}

crypto_status_t Crypto::encrypt_database(BYTE db_key[16], PBYTE db_serialized, ULONG db_size, PBYTE db_ct, BYTE iv[12], BYTE tag[16], DWORD flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, db_serialized, db_size, db_ct, db_size, tag, 16);
}

crypto_status_t Crypto::decrypt_database(BYTE db_key[16], PBYTE db_ct, ULONG db_size, BYTE iv[12], BYTE tag[16], PBYTE db_serialized)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, db_ct, db_size, db_serialized, db_size, tag, 16);
}

crypto_status_t Crypto::aes_init(BCRYPT_ALG_HANDLE *halgo, LPCWSTR algo_id, PBYTE chaining_mode,
	DWORD chaining_mode_len, BCRYPT_KEY_HANDLE *hkey, PBYTE key, ULONG key_len)
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(halgo, algo_id, NULL, 0);

	if (status != STATUS_SUCCESS)
	{
		// Error
		return CRYPTO_ERR_OPEN_PROVIDER;
	}

	if (chaining_mode != NULL)
	{
		status = BCryptSetProperty(*halgo, BCRYPT_CHAINING_MODE, chaining_mode, chaining_mode_len, 0);

		if (status != STATUS_SUCCESS)
		{
			// Error
			BCryptCloseAlgorithmProvider(*halgo, 0);
			return CRYPTO_ERR_SET_PROP;
		}
	}

	status = BCryptGenerateSymmetricKey(*halgo, hkey, NULL, 0, key, key_len, 0);

	if (status != STATUS_SUCCESS)
	{
		// Error
		BCryptCloseAlgorithmProvider(*halgo, 0);
		return CRYPTO_ERR_SET_KEY;
	}

	return CRYPTO_OK;
}

void Crypto::aes_close(BCRYPT_ALG_HANDLE *halgo, BCRYPT_KEY_HANDLE *hkey)
{
	if (*halgo != NULL)
	{
		BCryptCloseAlgorithmProvider(*halgo, 0);
	}

	if (*hkey != NULL)
	{
		BCryptDestroyKey(*hkey);
	}
}

crypto_status_t Crypto::aes_128_gcm_encrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE pt, DWORD pt_len, PBYTE ct, DWORD ct_sz, PBYTE tag, DWORD tag_len)
{
	BCRYPT_ALG_HANDLE halgo = NULL;
	BCRYPT_KEY_HANDLE hkey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
	DWORD ct_len;
	crypto_status_t rv = this->aes_init(&halgo, BCRYPT_AES_ALGORITHM, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), &hkey, key, 16);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
	authinfo.pbNonce = &nonce[0];
	authinfo.cbNonce = nonce_len;
	authinfo.pbTag = &tag[0];
	authinfo.cbTag = tag_len;

	NTSTATUS status = BCryptEncrypt(hkey, pt, pt_len, (PBYTE)&authinfo, NULL, 0, ct, ct_sz, &ct_len, 0);

	if (status != STATUS_SUCCESS)
	{
		rv = CRYPTO_ERR_ENCRYPT;
	}
	else
	{
		rv = CRYPTO_OK;
	}

	this->aes_close(&halgo, &hkey);
	return rv;
}

crypto_status_t Crypto::aes_128_gcm_decrypt(PBYTE key, PBYTE nonce, ULONG nonce_len, PBYTE ct, DWORD ct_len, PBYTE pt, DWORD pt_sz, PBYTE tag, DWORD tag_len)
{
	BCRYPT_ALG_HANDLE halgo = NULL;
	BCRYPT_KEY_HANDLE hkey = NULL;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authinfo;
	DWORD pt_len;
	crypto_status_t rv = this->aes_init(&halgo, BCRYPT_AES_ALGORITHM, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), &hkey, key, 16);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	BCRYPT_INIT_AUTH_MODE_INFO(authinfo);
	authinfo.pbNonce = &nonce[0];
	authinfo.cbNonce = nonce_len;
	authinfo.pbTag = &tag[0];
	authinfo.cbTag = tag_len;

	NTSTATUS status = BCryptDecrypt(hkey, ct, ct_len, (PBYTE)&authinfo, NULL, 0, pt, pt_sz, &pt_len, 0);

	if (status != STATUS_SUCCESS)
	{
		if (status == STATUS_AUTH_TAG_MISMATCH)
		{
			rv = CRYPTO_ERR_DECRYPT_AUTH;
		}
		else
		{
			rv = CRYPTO_ERR_DECRYPT;
		}
	}
	else
	{
		rv = CRYPTO_OK;
	}

	this->aes_close(&halgo, &hkey);
	return rv;
}

crypto_status_t Crypto::sha256_multi(PBYTE *messages, ULONG *lengths, BYTE md[32])
{
	BCRYPT_ALG_HANDLE halgo = NULL;
	BCRYPT_HASH_HANDLE hhash = NULL;
	DWORD hashobjlen;
	crypto_status_t rv = CRYPTO_ERR_UNKNOWN;
	PBYTE *message = messages;
	ULONG *length = lengths;
	DWORD result = 0;
	ULONG temp;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&halgo, BCRYPT_SHA256_ALGORITHM, NULL, 0);

	if (status != STATUS_SUCCESS)
	{
		return CRYPTO_ERR_OPEN_PROVIDER;
	}

	status = BCryptGetProperty(halgo, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashobjlen, sizeof(DWORD), &temp, 0);

	if (status != STATUS_SUCCESS)
	{
		BCryptCloseAlgorithmProvider(halgo, 0);
		return CRYPTO_ERR_CREATE_HASH;
	}

	PBYTE hashobject = new BYTE[hashobjlen];

	if (hashobject == NULL)
	{
		BCryptCloseAlgorithmProvider(halgo, 0);
		return CRYPTO_ERR_CREATE_HASH;
	}

	status = BCryptCreateHash(halgo, &hhash, hashobject, hashobjlen, NULL, 0, 0);

	if (status != STATUS_SUCCESS)
	{
		BCryptCloseAlgorithmProvider(halgo, 0);
		delete[] hashobject;
		return CRYPTO_ERR_CREATE_HASH;
	}

	while (*message != NULL)
	{
		status = BCryptHashData(hhash, *message, *length, 0);

		if (status != STATUS_SUCCESS)
		{
			rv = CRYPTO_ERR_HASH_DATA;
			goto cleanup;
		}

		++message;
		++length;
	}

	status = BCryptFinishHash(hhash, md, 32, 0);

	if (status != STATUS_SUCCESS)
	{
		rv = CRYPTO_ERR_FINISH_HASH;
	}
	else
	{
		rv = CRYPTO_OK;
	}

cleanup:
	delete[] hashobject;
	BCryptDestroyHash(hhash);
	BCryptCloseAlgorithmProvider(halgo, 0);

	return rv;
}

static const char pw_chars_lower[] = "abcdefghijklmnopqrstuvwxyz";
static const char pw_chars_upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char pw_chars_numeral[] = "0123456789";
static const char pw_chars_special[] = "!@#$%^&*";

// Randomly generate a password. Ensure it has at least one of each character type requested.
crypto_status_t Crypto::generate_password(PBYTE buffer, USHORT buffer_len, USHORT flags)
{
	static char chset[70];
	USHORT setsize = 0;
	UINT retries = 1000; // Make a failure extremely unlikely.
	// Store the index of each character subset in a struct. A -1 means we don't need that 
	// character type. Use the need_ flags to show what we still need to do. If we have to
	// retry a password gen, resed the need_ values from the set_* values.
	struct set_index_struct 
	{
		UINT set_lower = MAXUINT16;
		UINT set_upper = MAXUINT16;
		UINT set_numeral = MAXUINT16;
		UINT set_special = MAXUINT16;
		UINT need_lower = 0;
		UINT need_upper = 0;
		UINT need_numeral = 0;
		UINT need_special = 0;
	} set_index;
	USHORT i;

	if (flags == 0)
	{
		return CRYPTO_ERR_INVALID;
	}

	if (flags & NL_PWFLAG_LOWER)
	{
		memcpy(&chset[setsize], pw_chars_lower, 26);
		set_index.set_lower = setsize;
		setsize += 26;
	}

	if (flags & NL_PWFLAG_UPPER)
	{
		memcpy(&chset[setsize], pw_chars_upper, 26);
		set_index.set_upper = setsize;
		setsize += 26;
	}

	if (flags & NL_PWFLAG_NUMERIC)
	{
		memcpy(&chset[setsize], pw_chars_numeral, 10);
		set_index.set_numeral = setsize;
		setsize += 10;
	}

	if (flags & NL_PWFLAG_SPECIAL)
	{
		memcpy(&chset[setsize], pw_chars_special, 8);
		set_index.set_special = setsize;
		setsize += 8;
	}

	while (retries)
	{
		if (set_index.set_lower < MAXUINT16)
		{
			set_index.need_lower = 1;
		}

		if (set_index.set_upper < MAXUINT16)
		{
			set_index.need_upper = 1;
		}

		if (set_index.set_numeral < MAXUINT16)
		{
			set_index.need_numeral = 1;
		}

		if (set_index.set_special < MAXUINT16)
		{
			set_index.need_special = 1;
		}

		PBYTE bp = buffer;

		for (i = 0; i < buffer_len; ++i)
		{
			ULONGLONG r;

			if (!this->drng.random(setsize, &r))
			{
				return CRYPTO_ERR_DRNG;
			}

			*bp = chset[r]; ++bp;

			if (r >= set_index.set_special)
			{
				set_index.need_special = 0;
			}
			else if (r >= set_index.set_numeral)
			{
				set_index.need_numeral = 0;
			}
			else if (r >= set_index.set_upper)
			{
				set_index.need_upper = 0;
			}
			else
			{
				set_index.need_lower = 0;
			}
		}

		if (set_index.need_special || set_index.need_numeral || set_index.need_upper || set_index.need_lower)
		{
			--retries;
		}
		else
		{
			return CRYPTO_OK;
		}
	}

	return CRYPTO_ERR_DRNG;
}