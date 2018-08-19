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
#include "VaultFile.h"
#include "PasswordManagerError.h"

using namespace System::IO;
using namespace System;

VaultFile::VaultFile()
{
	header_size = _MIN_HEADER_LENGTH;
	header = gcnew array<Byte>(header_size);
	vault_size = 0;
	fsvault = nullptr;
	flag_new = false;
}

VaultFile::~VaultFile()
{
}

int VaultFile::create(String ^path)
{
	int rv = NL_STATUS_OK;

	if (String::IsNullOrWhiteSpace(path))
	{
		return NL_STATUS_BADFILE;
	}

	// We aren't allowed to overwrite a new file
	if (File::Exists(path))
	{
		return NL_STATUS_EXISTS;
	}

	try
	{
		fsvault = File::Create(path);
	}
	catch (UnauthorizedAccessException ^)
	{
		return NL_STATUS_PERM;
	}
	catch (ArgumentNullException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (ArgumentException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (PathTooLongException ^)
	{
		return NL_STATUS_SIZE;
	}
	catch (DirectoryNotFoundException ^)
	{
		return NL_STATUS_NOTFOUND;
	}
	catch (NotSupportedException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (...)
	{
		return NL_STATUS_UNKNOWN;
	}

	// Only close the current vault (if any) if we successfully create a new one.
	vaultpath = path;
	this->close(fsvault);
	
	flag_new = true;

	// Create our preliminary vault file.
	return NL_STATUS_OK;
}

int VaultFile::open_read(String ^path)
{
	int rv;
	FileStream ^fs;
	flag_new = false;

	if (String::IsNullOrWhiteSpace(path))
	{
		return NL_STATUS_BADFILE;
	}

	try
	{
		fs = File::OpenRead(path);
		if (fs->Length < header_size) return NL_STATUS_BADFILE;
	}
	catch (UnauthorizedAccessException ^)
	{
		return NL_STATUS_PERM;
	}
	catch (ArgumentNullException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (ArgumentException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (PathTooLongException ^)
	{
		return NL_STATUS_SIZE;
	}
	catch (DirectoryNotFoundException ^)
	{
		return NL_STATUS_NOTFOUND;
	}
	catch (NotSupportedException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (...)
	{
		return NL_STATUS_UNKNOWN;
	}

	// If we had a vault open before, close it and use the new file stream.
	this->close(fsvault);
	vaultpath = path;
	fsvault = fs;

	// Read the header
	rv = this->read_header();

	if (rv != NL_STATUS_OK)
	{
		this->close(fs);
	}

	return rv;
}

int VaultFile::open_write()
{
	// Create a temporary vault file alongside the original. Write to the
	// temp file. When we call finish_write(), we'll move it into place.
	String ^dname, ^fname;

	if (fsvault)
	{
		this->close(fsvault);
	}

	if (String::IsNullOrWhiteSpace(vaultpath))
	{
		return NL_STATUS_BADFILE;
	}

	dname = Path::GetDirectoryName(vaultpath);
	fname = "~" + Path::GetFileName(vaultpath);
	temppath = Path::Combine(dname, fname);

	try
	{
		fsvault = File::Create(temppath);
	}
	catch (UnauthorizedAccessException ^)
	{
		return NL_STATUS_PERM;
	}
	catch (ArgumentNullException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (ArgumentException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (PathTooLongException ^)
	{
		return NL_STATUS_SIZE;
	}
	catch (DirectoryNotFoundException ^)
	{
		return NL_STATUS_NOTFOUND;
	}
	catch (NotSupportedException ^)
	{
		return NL_STATUS_INVALID;
	}
	catch (...)
	{
		return NL_STATUS_UNKNOWN;
	}

	return NL_STATUS_OK;
}

int VaultFile::write_data(array<Byte> ^data)
{
	try
	{
		fsvault->Write(data, 0, data->Length);
	}
	catch (...)
	{
		return NL_STATUS_WRITE;
	}

	return NL_STATUS_OK;
}


int VaultFile::finish_write()
{
	String ^dname, ^fname, ^backup;
	bool replace = true;

	dname = Path::GetDirectoryName(vaultpath);
	fname = Path::GetFileNameWithoutExtension(vaultpath) + ".bkv";
	backup = Path::Combine(dname, fname);

	flag_new = false;

	this->close(fsvault);

	// Delete the previous backup copy.
	File::Delete(backup); // no exception thrown if it doesn't exist

	// If the vault file exists (ie, it's not newly-created), then make
	// a backup and move the new/temp file into place.
	//
	// Otherwise, just do a move.
	if (File::Exists(vaultpath))
	{
		File::Replace(temppath, vaultpath, backup, true);
	}
	else
	{
		File::Move(temppath, vaultpath);
	}

	return NL_STATUS_OK;
}

void VaultFile::close(FileStream ^stream)
{
	try
	{
		stream->Close();
	}
	catch (...)
	{
	}

	// If we didn't write anything to the file, delete it.
	try
	{
		if (FileInfo::FileInfo(vaultpath).Length == 0)
		{
			File::Delete(vaultpath);
		}
	}
	catch (...)
	{

	}
}

int VaultFile::read_header()
{
	try
	{
		fsvault->Seek(0, SeekOrigin::Begin);

		if (fsvault->Read(header, 0, header_size) < (int)header_size)
		{
			return NL_STATUS_BADFILE;
		}

		version = BitConverter::ToUInt16(header, 52);

		if (version != 1)
		{
			return NL_STATUS_VERSION;
		}

		vault_size = BitConverter::ToUInt32(header, 54);

		if (vault_size + 86 != fsvault->Length)
		{
			return NL_STATUS_BADFILE;
		}
	}
	catch (...)
	{
		return NL_STATUS_UNKNOWN;
	}

	return NL_STATUS_OK;
}

array<Byte> ^VaultFile::get_header()
{
	return header;
}

int VaultFile::get_vault(array<Byte> ^evaultdata)
{
	try
	{
		fsvault->Seek(header_size, SeekOrigin::Begin);

		if (fsvault->Read(evaultdata, 0, vault_size) < (int)vault_size)
		{
			return NL_STATUS_BADFILE;
		}
	}
	catch (...)
	{
		return NL_STATUS_UNKNOWN;
	}

	return NL_STATUS_OK;
}