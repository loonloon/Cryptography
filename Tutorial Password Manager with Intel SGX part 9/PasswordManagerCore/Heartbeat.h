#pragma once

#include "common.h"
#include "dllexport.h"

#define HEARTBEAT_INTERVAL_SECS	15	// 15 seconds 

class PASSWORDMANAGERCORE_API Heartbeat {
	class PasswordManagerCoreNative *nmgr;
	HANDLE timer;

	void start_timer();

public:
	Heartbeat();
	~Heartbeat();

	void set_manager(PasswordManagerCoreNative *nmgr_in);
	void heartbeat();

	void start();
	void stop();
};
