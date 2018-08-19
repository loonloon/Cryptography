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

#include <string.h>
#include <string>
#include "E_Crypto.h"
#include <sgx_tae_service.h>

using namespace std;

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

#define TRY_ASSIGN(x) try{x.assign(in,len);} catch(...){return 0;} return 1

#pragma pack(push,1)
struct vault_state_struct {
	sgx_time_t lastheartbeat;
	sgx_time_t lockafter;
	uint16_t lock_delay;
	uint64_t pid;
	char db_key[16];
};
#pragma pack(pop)

typedef vault_state_struct vault_state_t;

class E_AccountRecord
{
	char nonce[12];
	char tag[16];
	// Store these in their multibyte form. There's no sense in translating
	// them back to wchar_t since they have to be passed in and out as
	// char * anyway.
	string name, login, url, epass;

public:
	E_AccountRecord();
	~E_AccountRecord();

	void set_nonce(const char *in) { memcpy(nonce, in, 12); }
	void set_tag(const char *in) { memcpy(tag, in, 16); }

	int set_enc_pass(const char *in, uint16_t len) { TRY_ASSIGN(epass); }
	int set_name(const char *in, uint16_t len) { TRY_ASSIGN(name); }
	int set_login(const char *in, uint16_t len) { TRY_ASSIGN(login); }
	int set_url(const char *in, uint16_t len) { TRY_ASSIGN(url); }

	const char *get_epass() { return epass.c_str(); }
	const char *get_name() { return name.c_str(); }
	const char *get_login() { return login.c_str(); }
	const char *get_url() { return url.c_str(); }

	const char *get_nonce() { return (const char *)nonce; }
	const char *get_tag() { return (const char *)tag; }

	uint16_t get_name_len() { return (uint16_t) name.length(); }
	uint16_t get_login_len() { return (uint16_t) login.length(); }
	uint16_t get_url_len() { return (uint16_t) url.length(); }
	uint16_t get_epass_len() { return (uint16_t) epass.length(); }

	void clear();
};

class E_Vault
{
	E_Crypto crypto;
	char m_pw_salt[8];
	char db_key_nonce[12];
	char db_key_tag[16];
	char db_key_enc[16];
	char db_key[16];
	uint16_t db_version;
	uint32_t db_size; // Use get_db_size() to fetch this value so it gets updated as needed
	char db_data_nonce[12];
	char db_data_tag[16];
	char *db_data;
	uint32_t state, sealsz;
	// Cache the number of defined accounts so that the GUI doesn't have to fetch
	// "empty" account info unnecessarily.
	uint32_t naccounts;
	uint16_t lock_delay; // in seconds

	E_AccountRecord accounts[MAX_ACCOUNTS];

	void clear();
	void clear_account_info();

public:
	E_Vault();
	~E_Vault();

	int initialize();
	int initialize(const unsigned char *header, uint16_t size);
	int load_vault(const unsigned char *edata);

	int get_header(unsigned char *header, uint16_t *size);
	int get_vault(unsigned char *edate, uint32_t *size);

	uint32_t get_db_size();

	void lock();
	int unlock(const char *password);

	int set_master_password(const char *password);
	int change_master_password(const char *oldpass, const char *newpass);

	int accounts_get_count(uint32_t *count);

	int accounts_get_info_sizes(uint32_t idx, uint16_t *mbname_sz, uint16_t *mblogin_sz, uint16_t *mburl_sz);
	int accounts_get_info(uint32_t idx, char *mbname, uint16_t mbname_sz, char *mblogin, uint16_t mblogin_sz,
		char *mburl, uint16_t mburl_sz);

	int accounts_get_password_size(uint32_t idx, uint16_t *mbpass_sz);
	int accounts_get_password(uint32_t idx, char *mbpass, uint16_t mbpass_sz);

	int accounts_set_info(uint32_t idx, const char *mbname, uint16_t mbname_len, const char *mblogin, uint16_t mblogin_len,
		const char *mburl, uint16_t mburl_len);
	int accounts_set_password(uint32_t idx, const char *mbpass, uint16_t mbpass_len);

	int accounts_generate_password(uint16_t length, uint16_t pwflags, char *cpass);

	int is_valid() { return _VST_IS_VALID(state); }
	int is_locked() { return ((state&_VST_LOCKED) == _VST_LOCKED) ? 1 : 0; }

	uint32_t get_state_size();
	int heartbeat(char *state_data, uint32_t len);
	int restore_state(char *state_data, uint32_t len);

	// Enforce the maximum delay of 10 minutes in the enclave, too.
	void set_lock_delay(uint16_t mins) { lock_delay = 60 * ((mins > 10) ? 10 : mins); }
};

