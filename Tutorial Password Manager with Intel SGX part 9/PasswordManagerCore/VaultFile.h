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

using namespace System;
using namespace System::IO;

#define _MIN_HEADER_LENGTH	86

ref class VaultFile
{
	String ^vaultpath, ^temppath;
	FileStream ^fsvault;
	StreamWriter ^wvault;
	UInt16 version;
	UInt32 vault_size, header_size;
	array<Byte> ^header;
	Boolean flag_new;

	int read_header();

public:
	VaultFile();
	~VaultFile();

	int create(String ^path);
	int open_read(String ^path);
	void close() { close(fsvault); }
	void close(FileStream ^stream);
	int open_write();
	int write_data(array<Byte> ^data);
	int finish_write();

	UInt16 get_header_size() { return header_size; }
	UInt32 get_vault_size() { return vault_size; }
	String ^get_vault_path() { return vaultpath; }
	Boolean is_open() { return (fsvault && fsvault->CanRead); }
	Boolean is_new() { return flag_new; }

	int get_vault(array<Byte> ^evaultdata);
	array<Byte> ^get_header();
};

