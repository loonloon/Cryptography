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

#include "common.h"
#include "E_Crypto.h"
#include <sgx_tcrypto.h>
#include <string.h>

static void _xor_quads(void *dst, void *src, int n);

E_Crypto::E_Crypto(void)
{
}


E_Crypto::~E_Crypto(void)
{
}

crypto_status_t E_Crypto::generate_database_key(unsigned char key_out[16], GenerateDatabaseKeyCallback callback)
{
	unsigned long count = 0;

	while ((count = drng.get_seed_bytes(&key_out[count], 16)) < 16)
	{
		if (callback != NULL)
		{
			// So that the GUI can show a progress indicator, a cancel button, etc.
			int rv = callback(count, 16);
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

crypto_status_t E_Crypto::derive_master_key(unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char key_out[16])
{
	return this->derive_master_key_ex(passphrase, passphrase_len, salt, 8, CRYPTO_KDF_ITERATIONS, key_out);
}

crypto_status_t E_Crypto::derive_master_key_ex(unsigned char *passphrase, unsigned long passphrase_len, unsigned char *salt, unsigned long salt_len,
	unsigned long iterations, unsigned char key_out[16])
{
	unsigned char *messages[3] = { passphrase, salt, NULL };
	unsigned long lengths[3] = { passphrase_len, salt_len, 0 };
	unsigned char msg[32], md[32], key[32];
	crypto_status_t rv = CRYPTO_ERR_UNKNOWN;

	rv = this->sha256_multi(messages, lengths, md);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	memcpy(key, md, 32);
	messages[1] = msg;
	lengths[1] = 32;

	for (unsigned long i = 0; i < iterations; ++i)
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

	memcpy(key_out, &(key[16]), 16);
	return CRYPTO_OK;
}

crypto_status_t E_Crypto::unlock_vault(unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char db_key_ct[16], unsigned char db_key_iv[12], unsigned char db_key_tag[16], unsigned char db_key_pt[16])
{
	unsigned char mkey[16];
	crypto_status_t rv = this->derive_master_key(passphrase, passphrase_len, salt, mkey);

	if (rv != CRYPTO_OK)
	{
		return rv;
	}

	rv = this->decrypt_database_key(mkey, db_key_ct, db_key_iv, db_key_tag, db_key_pt);
	return rv;
}

crypto_status_t E_Crypto::validate_passphrase(unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char db_key_ct[16], unsigned char db_iv[12], unsigned char db_tag[16])
{
	return this->validate_passphrase_ex(passphrase, passphrase_len, salt, CRYPTO_KDF_SALT_LEN, CRYPTO_KDF_ITERATIONS, db_key_ct, db_iv, db_tag);
}

crypto_status_t E_Crypto::validate_passphrase_ex(unsigned char *passphrase, unsigned long passphrase_len, unsigned char *salt, unsigned long salt_len,
	unsigned long iterations, unsigned char db_key_ct[16], unsigned char db_iv[12], unsigned char db_tag[16])
{
	unsigned char db_key_pt[16]; // We discard this because we don't need it for this routine
	crypto_status_t rv = this->unlock_vault(passphrase, passphrase_len, salt, db_key_ct, db_iv, db_tag, db_key_pt);
	return rv;
}

crypto_status_t E_Crypto::generate_salt(unsigned char salt[8])
{
	return this->generate_salt_ex(salt, CRYPTO_KDF_SALT_LEN);
}

crypto_status_t E_Crypto::generate_salt_ex(unsigned char *salt, unsigned long salt_len)
{
	unsigned long n = drng.get_rand_bytes(salt, salt_len);

	if (n != salt_len)
	{
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::generate_nonce_gcm(unsigned char *nonce)
{
	unsigned long n = drng.get_rand_bytes(nonce, 12);

	if (n != 12)
	{
		// RDRAND should not fail unless something bad has happened.
		return CRYPTO_ERR_DRNG;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::encrypt_database_key(unsigned char master_key[16], unsigned char db_key_pt[16], unsigned char db_key_ct[16],
	unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(master_key, iv, 12, db_key_pt, 16, db_key_ct, tag);
}

crypto_status_t E_Crypto::decrypt_database_key(unsigned char master_key[16], unsigned char db_key_ct[16], unsigned char iv[12],
	unsigned char tag[16], unsigned char db_key_pt[16])
{
	return this->aes_128_gcm_decrypt(master_key, iv, 12, db_key_ct, 16, db_key_pt, tag);
}

crypto_status_t E_Crypto::encrypt_account_password(unsigned char db_key[16], unsigned char *password_pt, unsigned long password_len,
	unsigned char *password_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, password_pt, password_len, password_ct, tag);
}

crypto_status_t E_Crypto::decrypt_account_password(unsigned char db_key[16], unsigned char *password_ct, unsigned long password_len,
	unsigned char iv[12], unsigned char tag[16], unsigned char *password)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, password_ct, password_len, password, tag);
}

crypto_status_t E_Crypto::encrypt_database(unsigned char db_key[16], unsigned char *db_serialized, unsigned long db_size,
	unsigned char *db_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags)
{
	if (!(flags & CRYPTO_F_IV_PROVIDED))
	{
		crypto_status_t rv = this->generate_nonce_gcm(iv);

		if (rv != CRYPTO_OK)
		{
			return rv;
		}
	}

	return this->aes_128_gcm_encrypt(db_key, iv, 12, db_serialized, db_size, db_ct, tag);
}

crypto_status_t E_Crypto::decrypt_database(unsigned char db_key[16], unsigned char *db_ct, unsigned long db_size,
	unsigned char iv[12], unsigned char tag[16], unsigned char *db_serialized)
{
	return this->aes_128_gcm_decrypt(db_key, iv, 12, db_ct, db_size, db_serialized, tag);
}

//------------------------------------------------------------
// Private methods 
//------------------------------------------------------------
crypto_status_t E_Crypto::aes_128_gcm_encrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
	unsigned char *pt, unsigned long pt_len, unsigned char *ct, unsigned char *tag)
{
	sgx_status_t status = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t *)key, pt, pt_len, ct, nonce, nonce_len, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)tag);

	if (status != SGX_SUCCESS)
	{
		return CRYPTO_ERR_ENCRYPT;
	}

	return CRYPTO_OK;
}

crypto_status_t E_Crypto::aes_128_gcm_decrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
	unsigned char *ct, unsigned long ct_len, unsigned char *pt, unsigned char *tag)
{
	sgx_status_t status = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t *)key, ct, ct_len, pt, nonce, nonce_len, NULL, 0, (sgx_aes_gcm_128bit_tag_t *)tag);

	if (status != SGX_SUCCESS)
	{
		if (status == SGX_ERROR_MAC_MISMATCH)
		{
			return CRYPTO_ERR_DECRYPT_AUTH;
		}

		return CRYPTO_ERR_DECRYPT;
	}

	return CRYPTO_OK;
}


crypto_status_t E_Crypto::sha256_multi(unsigned char **messages, unsigned long *lengths, unsigned char hash[32])
{
	sgx_sha_state_handle_t hsha;
	unsigned char **message = messages;
	unsigned long *length = lengths;
	crypto_status_t rv = CRYPTO_ERR_UNKNOWN;

	sgx_status_t status = sgx_sha256_init(&hsha);

	if (status != SGX_SUCCESS)
	{
		return CRYPTO_ERR_CREATE_HASH;
	}

	while (*message != NULL)
	{
		status = sgx_sha256_update(*message, *length, hsha);

		if (status != SGX_SUCCESS)
		{
			rv = CRYPTO_ERR_HASH_DATA;
			goto cleanup;
		}

		++message;
		++length;
	}

	status = sgx_sha256_get_hash(hsha, (sgx_sha256_hash_t *)hash);

	if (status != SGX_SUCCESS)
	{
		rv = CRYPTO_ERR_FINISH_HASH;
		goto cleanup;
	}

	rv = CRYPTO_OK;

cleanup:
	sgx_sha256_close(hsha);

	return rv;
}

static const char pw_chars_lower[] = "abcdefghijklmnopqrstuvwxyz";
static const char pw_chars_upper[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char pw_chars_numeral[] = "0123456789";
static const char pw_chars_special[] = "!@#$%^&*";
#ifndef MAXUINT16
#define MAXUINT16 0xFFFF
#endif

// Randomly generate a password. Ensure it has at least one of each character type requested.
crypto_status_t E_Crypto::generate_password(unsigned char *buffer, uint16_t buffer_len, uint16_t flags)
{
	static char chset[70];
	uint16_t setsize = 0;
	unsigned int retries = 1000; // Make a failure extremely unlikely.
	// Store the index of each character subset in a struct. A -1 means we don't need that 
	// character type. Use the need_ flags to show what we still need to do. If we have to
	// retry a password gen, resed the need_ values from the set_* values.
	struct set_index_struct 
	{
		unsigned int set_lower = MAXUINT16;
		unsigned int set_upper = MAXUINT16;
		unsigned int set_numeral = MAXUINT16;
		unsigned int set_special = MAXUINT16;
		unsigned int need_lower = 0;
		unsigned int need_upper = 0;
		unsigned int need_numeral = 0;
		unsigned int need_special = 0;
	} set_index;

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

		unsigned char *bp = buffer;

		for (uint16_t i = 0; i < buffer_len; ++i) 
		{
			uint64_t r;

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