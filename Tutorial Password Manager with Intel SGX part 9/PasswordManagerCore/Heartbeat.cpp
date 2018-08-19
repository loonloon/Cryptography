#include "stdafx.h"
#include "Heartbeat.h"
#include "PasswordManagerCoreNative.h"

static void CALLBACK heartbeat_proc(PVOID param, BOOLEAN fired)
{
	Heartbeat *hb = (Heartbeat *)param;
	hb->heartbeat();
}

Heartbeat::Heartbeat()
{
	timer = NULL;
}

Heartbeat::~Heartbeat()
{
	if (timer == NULL)
	{
		DeleteTimerQueueTimer(NULL, &timer, NULL);
	}
}

void Heartbeat::set_manager(PasswordManagerCoreNative *nmgr_in)
{
	nmgr = nmgr_in;
}

void Heartbeat::heartbeat()
{
	// Call the heartbeat method in the native password manager
	// object. Restart the timer unless there was an error.
	if (nmgr->heartbeat())
	{
		start_timer();
	}
}

void Heartbeat::start()
{
	stop();

	// Perform our first heartbeat right away.
	if (nmgr->heartbeat())
	{
		start_timer();
	}
}

void Heartbeat::start_timer()
{
	// Set our heartbeat timer. Use the default Timer Queue
	CreateTimerQueueTimer(&timer, NULL, (WAITORTIMERCALLBACK)heartbeat_proc,
		(void *)this, HEARTBEAT_INTERVAL_SECS * 1000, 0, 0);
}

void Heartbeat::stop()
{
	// Stop the timer (if it exists)
	if (timer != NULL)
	{
		DeleteTimerQueueTimer(NULL, timer, NULL);
		timer = NULL;
	}
}