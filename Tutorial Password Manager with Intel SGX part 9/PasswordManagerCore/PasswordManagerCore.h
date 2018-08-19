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
#include "PasswordManagerCoreNative.h"
#include "VaultFile.h"

using namespace System;
using namespace System::Threading;
using namespace System::Security;
using namespace System::Drawing;

#define PWR_MSG_NONE		0x0000
#define PWR_MSG_SUSPEND		0x0001
#define PWR_MSG_RESUME		0x0002
#define PWR_MSG_OTHER		0x0003

#define _NL_CACHE_STALE		0
#define _NL_CACHE_OK		1

#define _VWRITE_HEADER		1
#define _VWRITE_ACCOUNTS	2
#define _VWRITE_ALL			_VWRITE_HEADER|_VWRITE_ACCOUNTS

#define RESUME_LOCKED		0x0
#define RESUME_UNLOCKED		0x1

namespace PasswordManager {

	public ref class PasswordFlag
	{
	public:
		literal int LowerCase = NL_PWFLAG_LOWER;
		literal int UpperCase = NL_PWFLAG_UPPER;
		literal int Numerals = NL_PWFLAG_NUMERIC;
		literal int SpecialChars = NL_PWFLAG_SPECIAL;
		literal int All = NL_PWFLAG_SPECIAL | NL_PWFLAG_NUMERIC | NL_PWFLAG_UPPER | NL_PWFLAG_LOWER;
	};

	public ref class ResumeVaultState {
	public:
		literal int Locked = RESUME_LOCKED;
		literal int Unlocked = RESUME_UNLOCKED;
	};

	public ref class PowerManagementMessage {
	public:
		literal int None = PWR_MSG_NONE;
		literal int Suspend = PWR_MSG_SUSPEND;
		literal int Resume = PWR_MSG_RESUME;
		literal int Other = PWR_MSG_OTHER;
	};

	public ref class PasswordManagerStatus
	{
	public:
		literal int OK = NL_STATUS_OK;
		literal int MemoryAllocation = NL_STATUS_ALLOC;
		literal int BadFile = NL_STATUS_BADFILE;
		literal int Clipboard = NL_STATUS_CLIPBOARD;
		literal int Exists = NL_STATUS_EXISTS;
		literal int Size = NL_STATUS_SIZE;
		literal int Range = NL_STATUS_RANGE;
		literal int NoPermission = NL_STATUS_PERM;
		literal int NotFound = NL_STATUS_NOTFOUND;
		literal int Invalid = NL_STATUS_INVALID;
		literal int IncorrectVersion = NL_STATUS_VERSION;
		literal int RandomGenerator = NL_STATUS_RAND;
		literal int UserCancelled = NL_STATUS_USER_CANCEL;
		literal int NoChange = NL_STATUS_NO_CHANGE;
		literal int PasswordIncorrect = NL_STATUS_PASSWORD;
		literal int CantUpdate = NL_STATUS_UPDATE;
		literal int WriteFailed = NL_STATUS_WRITE;
		literal int Mismatch = NL_STATUS_MISMATCH;
		literal int LostEnclave = NL_STATUS_LOST_ENCLAVE;
		literal int RecreatedEnclave = NL_STATUS_RECREATED_ENCLAVE;
	};

}

public ref class PowerManagement
{
	PowerManagement() {}
	~PowerManagement() {}
public:
	static UInt16 message(int msg, IntPtr wParam, IntPtr lParam);
};

public ref class PasswordManagerCore
{
	PasswordManagerCoreNative *_nlink;
	int cache_accounts;
	VaultFile ^vaultfile;
	SpinLock slock;
	bool restore_rv;

	int _vault_initialize();
	int _vault_reinitialize();
	int update_vault();
	int _vault_unlock(SecureString ^passphrase);
	int send_vault_data();

	bool restore_vault() { return restore_vault(false); }
	bool restore_vault(bool flag_async);

public:
	PasswordManagerCore();
	~PasswordManagerCore();

	void set_sgx_support();

	int vault_create(String ^path);
	int vault_open(String ^path);
	
	int vault_unlock(SecureString ^passphrase);
	void vault_lock();

	int set_master_password(SecureString ^password, SecureString ^confirm);
	int change_master_password(SecureString ^oldpss, SecureString ^newpass, SecureString ^confirm);

	int accounts_get_count(UInt32 %count);
	int accounts_get_info(UInt32 idx, SecureString ^%name, SecureString ^%login, SecureString ^%url);

	int accounts_get_password(UInt32 idx, SecureString ^%password);
	int accounts_view_password(UInt32 idx, IntPtr hptr);
	int accounts_password_to_clipboard(UInt32 idx);

	int accounts_set_info(UInt32 idx, SecureString ^name, SecureString ^login, SecureString ^url);
	int accounts_set_password(UInt32 idx, SecureString ^password);

	int generate_password(UInt16 length, UInt16 flags, SecureString ^%password);
	int generate_and_view_password(UInt16 length, UInt16 flags, SecureString ^%password, IntPtr hptr);

	void set_lock_timeout(UInt16 mins) { _nlink->set_lock_delay(mins); }
	
	void suspend();
	int resume();

	String ^error_msg(int);

	// Marshalling

	static LPWSTR M_SecureString_to_LPWSTR(SecureString ^ss);
	void M_Free_LPWSTR(LPWSTR ws);
};

