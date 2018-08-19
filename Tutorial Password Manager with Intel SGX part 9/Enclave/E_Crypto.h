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

#include "E_DRNG.h"

#define CRYPTO_KDF_ITERATIONS	5000
#define CRYPTO_KDF_SALT_LEN	8

#define CRYPTO_OK						0x00000000
#define CRYPTO_ERR_OPEN_PROVIDER		0x10000001
#define CRYPTO_ERR_CREATE_HASH			0x10000002
#define CRYPTO_ERR_HASH_DATA			0x10000003
#define CRYPTO_ERR_FINISH_HASH			0x10000004
#define CRYPTO_ERR_SET_PROP				0x10000005
#define CRYPTO_ERR_GET_PROP				0x10000006
#define CRYPTO_ERR_SET_KEY				0x10000007

#define CRYPTO_ERR_DECRYPT				0x10000010
#define CRYPTO_ERR_DECRYPT_AUTH			0x10000011
#define CRYPTO_ERR_ENCRYPT				0x10000012

#define CRYPTO_ERR_PASS_MISMATCH		0x10000100
#define CRYPTO_ERR_USER_CANCEL			0x10000101

#define CRYPTO_ERR_INVALID				0x10000200

#define CRYPTO_ERR_DRNG					0x20000001


#define CRYPTO_ERR_UNKNOWN				0xF0000001

#define CRYPTO_F_IV_PROVIDED			0x00000001

typedef int (*GenerateDatabaseKeyCallback)(int, int);
typedef unsigned long crypto_status_t;

class E_Crypto
{
	E_DRNG drng;

	crypto_status_t sha256_multi (unsigned char * *messages, unsigned long *lengths, unsigned char hash[32]);

	crypto_status_t aes_128_gcm_encrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
		unsigned char *pt, unsigned long pt_len, unsigned char *ct, unsigned char *tag);
	crypto_status_t aes_128_gcm_decrypt(unsigned char *key, unsigned char *nonce, unsigned long nonce_len,
		unsigned char *ct, unsigned long ct_len, unsigned char *pt, unsigned char *tag);

public:
	E_Crypto(void);
	~E_Crypto(void);

	crypto_status_t generate_database_key (unsigned char key_out[16], GenerateDatabaseKeyCallback callback);
	crypto_status_t generate_salt (unsigned char salt[8]);
	crypto_status_t generate_salt_ex (unsigned char * salt, unsigned long salt_len);
	crypto_status_t generate_nonce_gcm (unsigned char nonce[12]);

	crypto_status_t derive_master_key (unsigned char * passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char key_out[16]);
	crypto_status_t derive_master_key_ex (unsigned char * passphrase, unsigned long passphrase_len, unsigned char * salt, unsigned long salt_len, unsigned long iterations, unsigned char key_out[16]);

	crypto_status_t unlock_vault(unsigned char *passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char db_key_ct[16], unsigned char db_key_iv[12], unsigned char db_key_tag[16], unsigned char db_key_pt[16]);

	crypto_status_t validate_passphrase(unsigned char * passphrase, unsigned long passphrase_len, unsigned char salt[8], unsigned char db_key_ct[16], unsigned char db_iv[12], unsigned char db_tag[16]);
	crypto_status_t validate_passphrase_ex(unsigned char * passphrase, unsigned long passphrase_len, unsigned char * salt, unsigned long salt_len, unsigned long iterations, unsigned char db_key_ct[16], unsigned char db_iv[12], unsigned char db_tag[16]);

	crypto_status_t encrypt_database_key (unsigned char master_key[16], unsigned char db_key_pt[16], unsigned char db_key_ct[16], unsigned char iv[12], unsigned char tag[16], unsigned int flags= 0);
	crypto_status_t decrypt_database_key (unsigned char master_key[16], unsigned char db_key_ct[16], unsigned char iv[12], unsigned char tag[16], unsigned char db_key_pt[16]);

	crypto_status_t encrypt_account_password (unsigned char db_key[16], unsigned char * password_pt, unsigned long password_len, unsigned char * password_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags= 0);
	crypto_status_t decrypt_account_password (unsigned char db_key[16], unsigned char * password_ct, unsigned long password_len, unsigned char iv[12], unsigned char tag[16], unsigned char * password);

	crypto_status_t encrypt_database (unsigned char db_key[16], unsigned char * db_serialized, unsigned long db_size, unsigned char * db_ct, unsigned char iv[12], unsigned char tag[16], unsigned int flags= 0);
	crypto_status_t decrypt_database (unsigned char db_key[16], unsigned char * db_ct, unsigned long db_size, unsigned char iv[12], unsigned char tag[16], unsigned char * db_serialized);

	crypto_status_t generate_password(unsigned char *buffer, uint16_t buffer_len, uint16_t flags);
};
