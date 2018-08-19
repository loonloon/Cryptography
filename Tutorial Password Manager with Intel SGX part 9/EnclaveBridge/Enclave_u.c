#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ve_initialize_t {
	int ms_retval;
} ms_ve_initialize_t;

typedef struct ms_ve_initialize_from_header_t {
	int ms_retval;
	unsigned char* ms_header;
	uint16_t ms_len;
} ms_ve_initialize_from_header_t;

typedef struct ms_ve_load_vault_t {
	int ms_retval;
	unsigned char* ms_edata;
} ms_ve_load_vault_t;

typedef struct ms_ve_get_header_size_t {
	int ms_retval;
	uint16_t* ms_sz;
} ms_ve_get_header_size_t;

typedef struct ms_ve_get_header_t {
	int ms_retval;
	unsigned char* ms_header;
	uint16_t ms_len;
} ms_ve_get_header_t;

typedef struct ms_ve_get_vault_t {
	int ms_retval;
	unsigned char* ms_edata;
	uint32_t ms_len;
} ms_ve_get_vault_t;

typedef struct ms_ve_get_db_size_t {
	uint32_t ms_retval;
} ms_ve_get_db_size_t;

typedef struct ms_ve_unlock_t {
	int ms_retval;
	char* ms_password;
	size_t ms_password_len;
} ms_ve_unlock_t;

typedef struct ms_ve_set_master_password_t {
	int ms_retval;
	char* ms_password;
	size_t ms_password_len;
} ms_ve_set_master_password_t;

typedef struct ms_ve_change_master_password_t {
	int ms_retval;
	char* ms_oldpass;
	size_t ms_oldpass_len;
	char* ms_newpass;
	size_t ms_newpass_len;
} ms_ve_change_master_password_t;

typedef struct ms_ve_accounts_get_count_t {
	int ms_retval;
	uint32_t* ms_count;
} ms_ve_accounts_get_count_t;

typedef struct ms_ve_accounts_get_info_sizes_t {
	int ms_retval;
	uint32_t ms_idx;
	uint16_t* ms_mbname_sz;
	uint16_t* ms_mblogin_sz;
	uint16_t* ms_mburl_sz;
} ms_ve_accounts_get_info_sizes_t;

typedef struct ms_ve_accounts_get_info_t {
	int ms_retval;
	uint32_t ms_idx;
	char* ms_mbname;
	uint16_t ms_mbname_sz;
	char* ms_mblogin;
	uint16_t ms_mblogin_sz;
	char* ms_mburl;
	uint16_t ms_mburl_sz;
} ms_ve_accounts_get_info_t;

typedef struct ms_ve_accounts_get_password_size_t {
	int ms_retval;
	uint32_t ms_idx;
	uint16_t* ms_mbpass_sz;
} ms_ve_accounts_get_password_size_t;

typedef struct ms_ve_accounts_get_password_t {
	int ms_retval;
	uint32_t ms_idx;
	char* ms_mbpass;
	uint16_t ms_mbpass_sz;
} ms_ve_accounts_get_password_t;

typedef struct ms_ve_accounts_set_info_t {
	int ms_retval;
	uint32_t ms_idx;
	char* ms_mbname;
	size_t ms_mbname_len;
	//uint16_t ms_mbname_len;
	char* ms_mblogin;
	size_t ms_mblogin_len;
	//uint16_t ms_mblogin_len;
	char* ms_mburl;
	size_t ms_mburl_len;
	//uint16_t ms_mburl_len;
} ms_ve_accounts_set_info_t;

typedef struct ms_ve_accounts_set_password_t {
	int ms_retval;
	uint32_t ms_idx;
	char* ms_mbpass;
	size_t ms_mbpass_len;
	//uint16_t ms_mbpass_len;
} ms_ve_accounts_set_password_t;

typedef struct ms_ve_accounts_generate_password_t {
	int ms_retval;
	uint16_t ms_length;
	uint16_t ms_flags;
	char* ms_cpass;
} ms_ve_accounts_generate_password_t;

typedef struct ms_ve_is_valid_t {
	int ms_retval;
} ms_ve_is_valid_t;

typedef struct ms_ve_is_locked_t {
	int ms_retval;
} ms_ve_is_locked_t;

typedef struct ms_ve_get_state_size_t {
	uint32_t ms_retval;
} ms_ve_get_state_size_t;

typedef struct ms_ve_heartbeat_t {
	int ms_retval;
	char* ms_state;
	uint32_t ms_sz;
} ms_ve_heartbeat_t;

typedef struct ms_ve_set_lock_delay_t {
	uint16_t ms_mins;
} ms_ve_set_lock_delay_t;

typedef struct ms_ve_restore_state_t {
	int ms_retval;
	char* ms_state;
	uint32_t ms_sz;
} ms_ve_restore_state_t;

typedef struct ms_ve_o_process_info_t {
	uint64_t* ms_timestamp;
	uint64_t* ms_pid;
} ms_ve_o_process_info_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ve_o_process_info(void* pms)
{
	ms_ve_o_process_info_t* ms = SGX_CAST(ms_ve_o_process_info_t*, pms);
	ve_o_process_info(ms->ms_timestamp, ms->ms_pid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[6];
} ocall_table_Enclave = {
	6,
	{
		(void*)(uintptr_t)Enclave_ve_o_process_info,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t ve_initialize(sgx_enclave_id_t eid, int* retval)
{
	ms_ve_initialize_t ms;
	sgx_status_t status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_initialize_from_header(sgx_enclave_id_t eid, int* retval, unsigned char* header, uint16_t len)
{
	sgx_status_t status;
	ms_ve_initialize_from_header_t ms;
	ms.ms_header = header;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_load_vault(sgx_enclave_id_t eid, int* retval, unsigned char* edata)
{
	ms_ve_load_vault_t ms;
	ms.ms_edata = edata;
	sgx_status_t status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_get_header_size(sgx_enclave_id_t eid, int* retval, uint16_t* sz)
{
	ms_ve_get_header_size_t ms;
	ms.ms_sz = sz;
	sgx_status_t status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_get_header(sgx_enclave_id_t eid, int* retval, unsigned char* header, uint16_t len)
{
	ms_ve_get_header_t ms;
	ms.ms_header = header;
	ms.ms_len = len;
	sgx_status_t status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_get_vault(sgx_enclave_id_t eid, int* retval, unsigned char* edata, uint32_t len)
{
	ms_ve_get_vault_t ms;
	ms.ms_edata = edata;
	ms.ms_len = len;
	sgx_status_t status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_get_db_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	ms_ve_get_db_size_t ms;
	sgx_status_t status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_lock(sgx_enclave_id_t eid)
{
	sgx_status_t status = sgx_ecall(eid, 7, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ve_unlock(sgx_enclave_id_t eid, int* retval, char* password)
{
	ms_ve_unlock_t ms;
	ms.ms_password = (char*)password;
	ms.ms_password_len = password ? strlen(password) + 1 : 0;
	sgx_status_t status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_set_master_password(sgx_enclave_id_t eid, int* retval, char* password)
{
	ms_ve_set_master_password_t ms;
	ms.ms_password = (char*)password;
	ms.ms_password_len = password ? strlen(password) + 1 : 0;
	sgx_status_t status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_change_master_password(sgx_enclave_id_t eid, int* retval, char* oldpass, char* newpass)
{
	ms_ve_change_master_password_t ms;
	ms.ms_oldpass = (char*)oldpass;
	ms.ms_oldpass_len = oldpass ? strlen(oldpass) + 1 : 0;
	ms.ms_newpass = (char*)newpass;
	ms.ms_newpass_len = newpass ? strlen(newpass) + 1 : 0;
	sgx_status_t status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_get_count(sgx_enclave_id_t eid, int* retval, uint32_t* count)
{
	ms_ve_accounts_get_count_t ms;
	ms.ms_count = count;
	sgx_status_t status = sgx_ecall(eid, 11, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}
	return status;
}

sgx_status_t ve_accounts_get_info_sizes(sgx_enclave_id_t eid, int* retval, uint32_t idx, uint16_t* mbname_sz, uint16_t* mblogin_sz, uint16_t* mburl_sz)
{
	ms_ve_accounts_get_info_sizes_t ms;
	ms.ms_idx = idx;
	ms.ms_mbname_sz = mbname_sz;
	ms.ms_mblogin_sz = mblogin_sz;
	ms.ms_mburl_sz = mburl_sz;
	sgx_status_t status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_get_info(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbname, uint16_t mbname_sz, char* mblogin, uint16_t mblogin_sz, char* mburl, uint16_t mburl_sz)
{
	ms_ve_accounts_get_info_t ms;
	ms.ms_idx = idx;
	ms.ms_mbname = mbname;
	ms.ms_mbname_sz = mbname_sz;
	ms.ms_mblogin = mblogin;
	ms.ms_mblogin_sz = mblogin_sz;
	ms.ms_mburl = mburl;
	ms.ms_mburl_sz = mburl_sz;
	sgx_status_t status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_get_password_size(sgx_enclave_id_t eid, int* retval, uint32_t idx, uint16_t* mbpass_sz)
{
	ms_ve_accounts_get_password_size_t ms;
	ms.ms_idx = idx;
	ms.ms_mbpass_sz = mbpass_sz;
	sgx_status_t status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_get_password(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbpass, uint16_t mbpass_sz)
{
	ms_ve_accounts_get_password_t ms;
	ms.ms_idx = idx;
	ms.ms_mbpass = mbpass;
	ms.ms_mbpass_sz = mbpass_sz;
	sgx_status_t status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_set_info(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbname, uint16_t mbname_len, char* mblogin, uint16_t mblogin_len, char* mburl, uint16_t mburl_len)
{
	ms_ve_accounts_set_info_t ms;
	ms.ms_idx = idx;
	ms.ms_mbname = (char*)mbname;
	ms.ms_mbname_len = mbname ? strlen(mbname) + 1 : 0;
	ms.ms_mbname_len = mbname_len;
	ms.ms_mblogin = (char*)mblogin;
	ms.ms_mblogin_len = mblogin ? strlen(mblogin) + 1 : 0;
	ms.ms_mblogin_len = mblogin_len;
	ms.ms_mburl = (char*)mburl;
	ms.ms_mburl_len = mburl ? strlen(mburl) + 1 : 0;
	ms.ms_mburl_len = mburl_len;
	sgx_status_t status = sgx_ecall(eid, 16, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_set_password(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbpass, uint16_t mbpass_len)
{
	ms_ve_accounts_set_password_t ms;
	ms.ms_idx = idx;
	ms.ms_mbpass = (char*)mbpass;
	ms.ms_mbpass_len = mbpass ? strlen(mbpass) + 1 : 0;
	ms.ms_mbpass_len = mbpass_len;
	sgx_status_t status = sgx_ecall(eid, 17, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_accounts_generate_password(sgx_enclave_id_t eid, int* retval, uint16_t length, uint16_t flags, char* cpass)
{
	ms_ve_accounts_generate_password_t ms;
	ms.ms_length = length;
	ms.ms_flags = flags;
	ms.ms_cpass = cpass;
	sgx_status_t status = sgx_ecall(eid, 18, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_is_valid(sgx_enclave_id_t eid, int* retval)
{
	ms_ve_is_valid_t ms;
	sgx_status_t status = sgx_ecall(eid, 19, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_is_locked(sgx_enclave_id_t eid, int* retval)
{
	ms_ve_is_locked_t ms;
	sgx_status_t status = sgx_ecall(eid, 20, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_get_state_size(sgx_enclave_id_t eid, uint32_t* retval)
{
	ms_ve_get_state_size_t ms;
	sgx_status_t status = sgx_ecall(eid, 21, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_heartbeat(sgx_enclave_id_t eid, int* retval, char* state, uint32_t sz)
{
	ms_ve_heartbeat_t ms;
	ms.ms_state = state;
	ms.ms_sz = sz;
	sgx_status_t status = sgx_ecall(eid, 22, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

sgx_status_t ve_set_lock_delay(sgx_enclave_id_t eid, uint16_t mins)
{
	ms_ve_set_lock_delay_t ms;
	ms.ms_mins = mins;
	sgx_status_t status = sgx_ecall(eid, 23, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ve_restore_state(sgx_enclave_id_t eid, int* retval, char* state, uint32_t sz)
{
	ms_ve_restore_state_t ms;
	ms.ms_state = state;
	ms.ms_sz = sz;
	sgx_status_t status = sgx_ecall(eid, 24, &ocall_table_Enclave, &ms);

	if (status == SGX_SUCCESS && retval)
	{
		*retval = ms.ms_retval;
	}

	return status;
}

