#include "stdafx.h"
#include "AccountInfo.h"
#include "Pack.h"
#include "PasswordManagerError.h"
#include <Windows.h>
#include <string>

using namespace std;
using namespace Pack;

AccountInfo::AccountInfo(void)
{
}

void AccountInfo::clear()
{
	name->Clear();
	login->Clear();
	url->Clear();
}
