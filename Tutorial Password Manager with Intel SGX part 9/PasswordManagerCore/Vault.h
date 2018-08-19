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
#include <Windows.h>
#include <NCrypt.h>
#include <NCryptprotect.h>
#include "Crypto.h"

#define MAX_ACCOUNTS 8
#define MAX_VAULT_VERSION	1

#define _VST_DBKEY			0x00000001UL
#define _VST_MPASS			0x00000002UL
#define _VST_UPDSIZE		0x00000004UL

#define _VST_LOCKED			0x00001000UL

#define _VST_VALID_BITS		(_VST_DBKEY|_VST_MPASS)
#define _VST_IS_VALID(x)	((x&_VST_VALID_BITS)==_VST_VALID_BITS)?1:0

#define _VST_SET(x)			state|=x
#define _VST_CLEAR(x)		state&=~(x)
#define _VST_ISSET(x)		((state&x)==x)?1:0

typedef struct vault_state_struct {
	time_t lastheartbeat;
	DWORD pid;
	char iv[12];
	char tag[16];
} vault_state_t;

class PASSWORDMANAGERCORE_API AccountRecord
{
	char nonce[12];
	char tag[16];
	// Store these in their multibyte form. There's no sense in translating
	// them back to wchar_t since they have to be passed in and out as
	// char * anyway.
	char *name;
	char *login;
	char *url;
	char *epass;
	UINT16 epass_len; // Can't rely on NULL termination! It's an encrypted string.

	int set_field(char **field, const char *value, UINT16 len);
	void zero_free_field(char *field, UINT16 len);

public:
	AccountRecord();
	~AccountRecord();

	void set_nonce(const char *in) { memcpy(nonce, in, 12); }
	void set_tag(const char *in) { memcpy(tag, in, 16); }

	int set_enc_pass(const char *in, UINT16 len);
	int set_name(const char *in, UINT16 len) { return set_field(&name, in, len); }
	int set_login(const char *in, UINT16 len) { return set_field(&login, in, len); }
	int set_url(const char *in, UINT16 len) { return set_field(&url, in, len); }

	const char *get_epass() { return (epass == NULL)? "" : (const char *)epass; }
	const char *get_name() { return (name == NULL) ? "" : (const char *)name; }
	const char *get_login() { return (login == NULL) ? "" : (const char *)login; }
	const char *get_url() { return (url == NULL) ? "" : (const char *)url; }
	const char *get_nonce() { return (const char *)nonce; }
	const char *get_tag() { return (const char *)tag; }

	UINT16 get_name_len() { return (name == NULL) ? 0 : (UINT16)strlen(name); }
	UINT16 get_login_len() { return (login == NULL) ? 0 : (UINT16)strlen(login); }
	UINT16 get_url_len() { return (url == NULL) ? 0 : (UINT16)strlen(url); }
	UINT16 get_epass_len() { return (epass == NULL) ? 0 : epass_len; }

	void clear();
};

class PASSWORDMANAGERCORE_API Vault
{
	Crypto crypto;
	char m_pw_salt[8];
	char db_key_nonce[12];
	char db_key_tag[16];
	char db_key_enc[16];
	char db_key_obs[16];
	char db_key_xor[16];
	UINT16 db_version;
	UINT32 db_size; // Use get_db_size() to fetch this value so it gets updated as needed
	char db_data_nonce[12];
	char db_data_tag[16];
	char *db_data;
	NCRYPT_DESCRIPTOR_HANDLE h_db_key;
	PBYTE db_key_prot;
	ULONG db_key_prot_sz;
	UINT32 state;
	UINT16 lock_delay; // in seconds
	// Cache the number of defined accounts so that the GUI doesn't have to fetch
	// "empty" account info unnecessarily.
	UINT32 naccounts;
	int flag_dpapi;

	AccountRecord accounts[MAX_ACCOUNTS];

	void clear();
	void clear_account_info();

	void get_db_key(char key[16]);
	void set_db_key(const char key[16]);

public:
	Vault();
	~Vault();

	int initialize();
	int initialize(const unsigned char *header, UINT16 size);
	int load_vault(const unsigned char *edata);

	int get_header(unsigned char *header, UINT16 *size);
	int get_vault(unsigned char *edata, UINT32 *size);

	UINT32 get_db_size();

	void lock();
	int unlock(const char *password);

	int set_master_password(const char *password);
	int change_master_password(const char *oldpass, const char *newpass);

	int accounts_get_count(UINT32 *count);
	int accounts_get_info_sizes(UINT32 idx, UINT16 *mbname_sz, UINT16 *mblogin_sz, UINT16 *mburl_sz);
	int accounts_get_info(UINT32 idx, char *mbname, UINT16 mbname_sz, char *mblogin, UINT16 mblogin_sz,
		char *mburl, UINT16 mburl_sz);

	int accounts_get_password_size(UINT32 idx, UINT16 *mbpass_sz);
	int accounts_get_password(UINT32 idx, char *mbpass, UINT16 mbpass_sz);

	int accounts_set_info(UINT32 idx, const char *mbname, UINT16 mbname_len, const char *mblogin, UINT16 mblogin_len,
		const char *mburl, UINT16 mburl_len);
	int accounts_set_password(UINT32 idx, const char *mbpass, UINT16 mbpass_len);

	int accounts_generate_password(UINT16 length, UINT16 pwflags, char *cpass);

	int is_valid() { return _VST_IS_VALID(state); }
	int is_locked() { return ((state&_VST_LOCKED) == _VST_LOCKED) ? 1 : 0; }

	int heartbeat(char *state_data);
	UINT32 get_state_size() { return sizeof(vault_state_t); }
	int check_state(char *state_data, UINT32 state_size);

	void set_lock_delay(UINT16 mins) { lock_delay = 60 * ((mins > 10) ? 10 : mins); }
};

