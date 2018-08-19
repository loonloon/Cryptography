#pragma once

using namespace System;
using namespace System::Security;

ref class AccountInfo
{
	SecureString ^name, ^login, ^url;

public:
	AccountInfo(void);
	void set_name(SecureString ^in) { name = in; }
	void set_login(SecureString ^in) { login = in; }
	void set_url(SecureString ^in) { url = in; }

	void clear();

	SecureString ^get_name () { return name; }
	SecureString ^get_login() { return login; }
	SecureString ^get_url() { return url; }
};

