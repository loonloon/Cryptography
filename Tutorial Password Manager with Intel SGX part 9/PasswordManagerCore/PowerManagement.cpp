#include "stdafx.h"
#include "PasswordManagerCore.h"
#include <Windows.h>
#include <vcclr.h>

using namespace System;
using namespace System::Runtime::InteropServices;

UINT16 PowerManagement::message(int msg, IntPtr wParam, IntPtr lParam)
{
	INT32 subcode;

	// We only care about power-related messages
	if (msg != WM_POWERBROADCAST)
	{
		return PWR_MSG_NONE;
	}

	subcode = wParam.ToInt32();

	/*
	How wakeup events are handled in Windows:

		1. If the system wakes automatically (due to a timer or other event), it sends PBT_APMRESUMEAUTOMATIC to all applications.
		2. If the system wakes due to user activity, it sends PBT_APMRESUMEAUTOMATIC followed by PBT_APMRESUMESUSPEND.

	We don't want to process two signals for the same wakeup event, so we'll capture PBT_APMRESUMEAUTOMATIC.
	Most interactive applications do the opposite: ignore PBT_APMRESUMEAUTOMATIC and only act on
	PBT_APMRESUMESUSPEND. In our case, we want the vault to lock if it is supposed to, and the enclave to
	be recreated (and recoveed, if it is supposed), no matter how the system wakes up.
	*/

	if (subcode == PBT_APMRESUMEAUTOMATIC)
	{
		return PWR_MSG_RESUME;
	}
	else if (subcode == PBT_APMSUSPEND)
	{
		return PWR_MSG_SUSPEND;
	}

	// Don't care about other power events.
	return PWR_MSG_OTHER;
}