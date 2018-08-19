#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ve_initialize(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_initialize_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_initialize_t* ms = SGX_CAST(ms_ve_initialize_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ve_initialize();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_initialize_from_header(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_initialize_from_header_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_initialize_from_header_t* ms = SGX_CAST(ms_ve_initialize_from_header_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_header = ms->ms_header;
	uint16_t _tmp_len = ms->ms_len;
	size_t _len_header = _tmp_len * sizeof(*_tmp_header);
	unsigned char* _in_header = NULL;

	if (sizeof(*_tmp_header) != 0 &&
		(size_t)_tmp_len > (SIZE_MAX / sizeof(*_tmp_header))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_header, _len_header);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_header != NULL && _len_header != 0) {
		_in_header = (unsigned char*)malloc(_len_header);
		if (_in_header == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_header, _tmp_header, _len_header);
	}

	ms->ms_retval = ve_initialize_from_header(_in_header, _tmp_len);
err:
	if (_in_header) free(_in_header);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_load_vault(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_load_vault_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_load_vault_t* ms = SGX_CAST(ms_ve_load_vault_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_edata = ms->ms_edata;



	ms->ms_retval = ve_load_vault(_tmp_edata);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_get_header_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_get_header_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_get_header_size_t* ms = SGX_CAST(ms_ve_get_header_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint16_t* _tmp_sz = ms->ms_sz;
	size_t _len_sz = sizeof(*_tmp_sz);
	uint16_t* _in_sz = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sz, _len_sz);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sz != NULL && _len_sz != 0) {
		if ((_in_sz = (uint16_t*)malloc(_len_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sz, 0, _len_sz);
	}

	ms->ms_retval = ve_get_header_size(_in_sz);
err:
	if (_in_sz) {
		memcpy(_tmp_sz, _in_sz, _len_sz);
		free(_in_sz);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_get_header(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_get_header_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_get_header_t* ms = SGX_CAST(ms_ve_get_header_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_header = ms->ms_header;
	uint16_t _tmp_len = ms->ms_len;
	size_t _len_header = _tmp_len * sizeof(*_tmp_header);
	unsigned char* _in_header = NULL;

	if (sizeof(*_tmp_header) != 0 &&
		(size_t)_tmp_len > (SIZE_MAX / sizeof(*_tmp_header))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_header, _len_header);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_header != NULL && _len_header != 0) {
		if ((_in_header = (unsigned char*)malloc(_len_header)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_header, 0, _len_header);
	}

	ms->ms_retval = ve_get_header(_in_header, _tmp_len);
err:
	if (_in_header) {
		memcpy(_tmp_header, _in_header, _len_header);
		free(_in_header);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_get_vault(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_get_vault_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_get_vault_t* ms = SGX_CAST(ms_ve_get_vault_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_edata = ms->ms_edata;



	ms->ms_retval = ve_get_vault(_tmp_edata, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_get_db_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_get_db_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_get_db_size_t* ms = SGX_CAST(ms_ve_get_db_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ve_get_db_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_lock(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ve_lock();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_unlock(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_unlock_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_unlock_t* ms = SGX_CAST(ms_ve_unlock_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_password = ms->ms_password;
	size_t _len_password = ms->ms_password_len ;
	char* _in_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ve_unlock(_in_password);
err:
	if (_in_password) free(_in_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_set_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_set_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_set_master_password_t* ms = SGX_CAST(ms_ve_set_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_password = ms->ms_password;
	size_t _len_password = ms->ms_password_len ;
	char* _in_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_password, _len_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_password != NULL && _len_password != 0) {
		_in_password = (char*)malloc(_len_password);
		if (_in_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_password, _tmp_password, _len_password);
		_in_password[_len_password - 1] = '\0';
		if (_len_password != strlen(_in_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ve_set_master_password(_in_password);
err:
	if (_in_password) free(_in_password);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_change_master_password_t* ms = SGX_CAST(ms_ve_change_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_oldpass = ms->ms_oldpass;
	size_t _len_oldpass = ms->ms_oldpass_len ;
	char* _in_oldpass = NULL;
	char* _tmp_newpass = ms->ms_newpass;
	size_t _len_newpass = ms->ms_newpass_len ;
	char* _in_newpass = NULL;

	CHECK_UNIQUE_POINTER(_tmp_oldpass, _len_oldpass);
	CHECK_UNIQUE_POINTER(_tmp_newpass, _len_newpass);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_oldpass != NULL && _len_oldpass != 0) {
		_in_oldpass = (char*)malloc(_len_oldpass);
		if (_in_oldpass == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_oldpass, _tmp_oldpass, _len_oldpass);
		_in_oldpass[_len_oldpass - 1] = '\0';
		if (_len_oldpass != strlen(_in_oldpass) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_newpass != NULL && _len_newpass != 0) {
		_in_newpass = (char*)malloc(_len_newpass);
		if (_in_newpass == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_newpass, _tmp_newpass, _len_newpass);
		_in_newpass[_len_newpass - 1] = '\0';
		if (_len_newpass != strlen(_in_newpass) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ve_change_master_password(_in_oldpass, _in_newpass);
err:
	if (_in_oldpass) free(_in_oldpass);
	if (_in_newpass) free(_in_newpass);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_get_count(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_get_count_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_get_count_t* ms = SGX_CAST(ms_ve_accounts_get_count_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint32_t* _tmp_count = ms->ms_count;
	size_t _len_count = sizeof(*_tmp_count);
	uint32_t* _in_count = NULL;

	CHECK_UNIQUE_POINTER(_tmp_count, _len_count);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_count != NULL && _len_count != 0) {
		if ((_in_count = (uint32_t*)malloc(_len_count)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_count, 0, _len_count);
	}

	ms->ms_retval = ve_accounts_get_count(_in_count);
err:
	if (_in_count) {
		memcpy(_tmp_count, _in_count, _len_count);
		free(_in_count);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_get_info_sizes(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_get_info_sizes_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_get_info_sizes_t* ms = SGX_CAST(ms_ve_accounts_get_info_sizes_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint16_t* _tmp_mbname_sz = ms->ms_mbname_sz;
	size_t _len_mbname_sz = sizeof(*_tmp_mbname_sz);
	uint16_t* _in_mbname_sz = NULL;
	uint16_t* _tmp_mblogin_sz = ms->ms_mblogin_sz;
	size_t _len_mblogin_sz = sizeof(*_tmp_mblogin_sz);
	uint16_t* _in_mblogin_sz = NULL;
	uint16_t* _tmp_mburl_sz = ms->ms_mburl_sz;
	size_t _len_mburl_sz = sizeof(*_tmp_mburl_sz);
	uint16_t* _in_mburl_sz = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mbname_sz, _len_mbname_sz);
	CHECK_UNIQUE_POINTER(_tmp_mblogin_sz, _len_mblogin_sz);
	CHECK_UNIQUE_POINTER(_tmp_mburl_sz, _len_mburl_sz);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbname_sz != NULL && _len_mbname_sz != 0) {
		if ((_in_mbname_sz = (uint16_t*)malloc(_len_mbname_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mbname_sz, 0, _len_mbname_sz);
	}
	if (_tmp_mblogin_sz != NULL && _len_mblogin_sz != 0) {
		if ((_in_mblogin_sz = (uint16_t*)malloc(_len_mblogin_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mblogin_sz, 0, _len_mblogin_sz);
	}
	if (_tmp_mburl_sz != NULL && _len_mburl_sz != 0) {
		if ((_in_mburl_sz = (uint16_t*)malloc(_len_mburl_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mburl_sz, 0, _len_mburl_sz);
	}

	ms->ms_retval = ve_accounts_get_info_sizes(ms->ms_idx, _in_mbname_sz, _in_mblogin_sz, _in_mburl_sz);
err:
	if (_in_mbname_sz) {
		memcpy(_tmp_mbname_sz, _in_mbname_sz, _len_mbname_sz);
		free(_in_mbname_sz);
	}
	if (_in_mblogin_sz) {
		memcpy(_tmp_mblogin_sz, _in_mblogin_sz, _len_mblogin_sz);
		free(_in_mblogin_sz);
	}
	if (_in_mburl_sz) {
		memcpy(_tmp_mburl_sz, _in_mburl_sz, _len_mburl_sz);
		free(_in_mburl_sz);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_get_info(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_get_info_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_get_info_t* ms = SGX_CAST(ms_ve_accounts_get_info_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mbname = ms->ms_mbname;
	uint16_t _tmp_mbname_sz = ms->ms_mbname_sz;
	size_t _len_mbname = _tmp_mbname_sz * sizeof(*_tmp_mbname);
	char* _in_mbname = NULL;
	char* _tmp_mblogin = ms->ms_mblogin;
	uint16_t _tmp_mblogin_sz = ms->ms_mblogin_sz;
	size_t _len_mblogin = _tmp_mblogin_sz * sizeof(*_tmp_mblogin);
	char* _in_mblogin = NULL;
	char* _tmp_mburl = ms->ms_mburl;
	uint16_t _tmp_mburl_sz = ms->ms_mburl_sz;
	size_t _len_mburl = _tmp_mburl_sz * sizeof(*_tmp_mburl);
	char* _in_mburl = NULL;

	if (sizeof(*_tmp_mbname) != 0 &&
		(size_t)_tmp_mbname_sz > (SIZE_MAX / sizeof(*_tmp_mbname))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_mblogin) != 0 &&
		(size_t)_tmp_mblogin_sz > (SIZE_MAX / sizeof(*_tmp_mblogin))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (sizeof(*_tmp_mburl) != 0 &&
		(size_t)_tmp_mburl_sz > (SIZE_MAX / sizeof(*_tmp_mburl))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_mbname, _len_mbname);
	CHECK_UNIQUE_POINTER(_tmp_mblogin, _len_mblogin);
	CHECK_UNIQUE_POINTER(_tmp_mburl, _len_mburl);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbname != NULL && _len_mbname != 0) {
		if ((_in_mbname = (char*)malloc(_len_mbname)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mbname, 0, _len_mbname);
	}
	if (_tmp_mblogin != NULL && _len_mblogin != 0) {
		if ((_in_mblogin = (char*)malloc(_len_mblogin)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mblogin, 0, _len_mblogin);
	}
	if (_tmp_mburl != NULL && _len_mburl != 0) {
		if ((_in_mburl = (char*)malloc(_len_mburl)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mburl, 0, _len_mburl);
	}

	ms->ms_retval = ve_accounts_get_info(ms->ms_idx, _in_mbname, _tmp_mbname_sz, _in_mblogin, _tmp_mblogin_sz, _in_mburl, _tmp_mburl_sz);
err:
	if (_in_mbname) {
		memcpy(_tmp_mbname, _in_mbname, _len_mbname);
		free(_in_mbname);
	}
	if (_in_mblogin) {
		memcpy(_tmp_mblogin, _in_mblogin, _len_mblogin);
		free(_in_mblogin);
	}
	if (_in_mburl) {
		memcpy(_tmp_mburl, _in_mburl, _len_mburl);
		free(_in_mburl);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_get_password_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_get_password_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_get_password_size_t* ms = SGX_CAST(ms_ve_accounts_get_password_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint16_t* _tmp_mbpass_sz = ms->ms_mbpass_sz;
	size_t _len_mbpass_sz = sizeof(*_tmp_mbpass_sz);
	uint16_t* _in_mbpass_sz = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mbpass_sz, _len_mbpass_sz);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbpass_sz != NULL && _len_mbpass_sz != 0) {
		if ((_in_mbpass_sz = (uint16_t*)malloc(_len_mbpass_sz)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mbpass_sz, 0, _len_mbpass_sz);
	}

	ms->ms_retval = ve_accounts_get_password_size(ms->ms_idx, _in_mbpass_sz);
err:
	if (_in_mbpass_sz) {
		memcpy(_tmp_mbpass_sz, _in_mbpass_sz, _len_mbpass_sz);
		free(_in_mbpass_sz);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_get_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_get_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_get_password_t* ms = SGX_CAST(ms_ve_accounts_get_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mbpass = ms->ms_mbpass;
	uint16_t _tmp_mbpass_sz = ms->ms_mbpass_sz;
	size_t _len_mbpass = _tmp_mbpass_sz * sizeof(*_tmp_mbpass);
	char* _in_mbpass = NULL;

	if (sizeof(*_tmp_mbpass) != 0 &&
		(size_t)_tmp_mbpass_sz > (SIZE_MAX / sizeof(*_tmp_mbpass))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_mbpass, _len_mbpass);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbpass != NULL && _len_mbpass != 0) {
		if ((_in_mbpass = (char*)malloc(_len_mbpass)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_mbpass, 0, _len_mbpass);
	}

	ms->ms_retval = ve_accounts_get_password(ms->ms_idx, _in_mbpass, _tmp_mbpass_sz);
err:
	if (_in_mbpass) {
		memcpy(_tmp_mbpass, _in_mbpass, _len_mbpass);
		free(_in_mbpass);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_set_info(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_set_info_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_set_info_t* ms = SGX_CAST(ms_ve_accounts_set_info_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mbname = ms->ms_mbname;
	size_t _len_mbname = ms->ms_mbname_len ;
	char* _in_mbname = NULL;
	char* _tmp_mblogin = ms->ms_mblogin;
	size_t _len_mblogin = ms->ms_mblogin_len ;
	char* _in_mblogin = NULL;
	char* _tmp_mburl = ms->ms_mburl;
	size_t _len_mburl = ms->ms_mburl_len ;
	char* _in_mburl = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mbname, _len_mbname);
	CHECK_UNIQUE_POINTER(_tmp_mblogin, _len_mblogin);
	CHECK_UNIQUE_POINTER(_tmp_mburl, _len_mburl);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbname != NULL && _len_mbname != 0) {
		_in_mbname = (char*)malloc(_len_mbname);
		if (_in_mbname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mbname, _tmp_mbname, _len_mbname);
		_in_mbname[_len_mbname - 1] = '\0';
		if (_len_mbname != strlen(_in_mbname) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_mblogin != NULL && _len_mblogin != 0) {
		_in_mblogin = (char*)malloc(_len_mblogin);
		if (_in_mblogin == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mblogin, _tmp_mblogin, _len_mblogin);
		_in_mblogin[_len_mblogin - 1] = '\0';
		if (_len_mblogin != strlen(_in_mblogin) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_mburl != NULL && _len_mburl != 0) {
		_in_mburl = (char*)malloc(_len_mburl);
		if (_in_mburl == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mburl, _tmp_mburl, _len_mburl);
		_in_mburl[_len_mburl - 1] = '\0';
		if (_len_mburl != strlen(_in_mburl) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ve_accounts_set_info(ms->ms_idx, _in_mbname, ms->ms_mbname_len, _in_mblogin, ms->ms_mblogin_len, _in_mburl, ms->ms_mburl_len);
err:
	if (_in_mbname) free(_in_mbname);
	if (_in_mblogin) free(_in_mblogin);
	if (_in_mburl) free(_in_mburl);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_set_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_set_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_set_password_t* ms = SGX_CAST(ms_ve_accounts_set_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_mbpass = ms->ms_mbpass;
	size_t _len_mbpass = ms->ms_mbpass_len ;
	char* _in_mbpass = NULL;

	CHECK_UNIQUE_POINTER(_tmp_mbpass, _len_mbpass);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_mbpass != NULL && _len_mbpass != 0) {
		_in_mbpass = (char*)malloc(_len_mbpass);
		if (_in_mbpass == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_mbpass, _tmp_mbpass, _len_mbpass);
		_in_mbpass[_len_mbpass - 1] = '\0';
		if (_len_mbpass != strlen(_in_mbpass) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ve_accounts_set_password(ms->ms_idx, _in_mbpass, ms->ms_mbpass_len);
err:
	if (_in_mbpass) free(_in_mbpass);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_accounts_generate_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_accounts_generate_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_accounts_generate_password_t* ms = SGX_CAST(ms_ve_accounts_generate_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_cpass = ms->ms_cpass;
	uint16_t _tmp_length = ms->ms_length;
	size_t _len_cpass = _tmp_length * sizeof(*_tmp_cpass);
	char* _in_cpass = NULL;

	if (sizeof(*_tmp_cpass) != 0 &&
		(size_t)_tmp_length > (SIZE_MAX / sizeof(*_tmp_cpass))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_cpass, _len_cpass);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_cpass != NULL && _len_cpass != 0) {
		if ((_in_cpass = (char*)malloc(_len_cpass)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_cpass, 0, _len_cpass);
	}

	ms->ms_retval = ve_accounts_generate_password(_tmp_length, ms->ms_flags, _in_cpass);
err:
	if (_in_cpass) {
		memcpy(_tmp_cpass, _in_cpass, _len_cpass);
		free(_in_cpass);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_is_valid(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_is_valid_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_is_valid_t* ms = SGX_CAST(ms_ve_is_valid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ve_is_valid();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_is_locked(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_is_locked_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_is_locked_t* ms = SGX_CAST(ms_ve_is_locked_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ve_is_locked();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_get_state_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_get_state_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_get_state_size_t* ms = SGX_CAST(ms_ve_get_state_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = ve_get_state_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_heartbeat(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_heartbeat_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_heartbeat_t* ms = SGX_CAST(ms_ve_heartbeat_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_state = ms->ms_state;
	uint32_t _tmp_sz = ms->ms_sz;
	size_t _len_state = _tmp_sz * sizeof(*_tmp_state);
	char* _in_state = NULL;

	if (sizeof(*_tmp_state) != 0 &&
		(size_t)_tmp_sz > (SIZE_MAX / sizeof(*_tmp_state))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_state, _len_state);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_state != NULL && _len_state != 0) {
		if ((_in_state = (char*)malloc(_len_state)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_state, 0, _len_state);
	}

	ms->ms_retval = ve_heartbeat(_in_state, _tmp_sz);
err:
	if (_in_state) {
		memcpy(_tmp_state, _in_state, _len_state);
		free(_in_state);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_set_lock_delay(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_set_lock_delay_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_set_lock_delay_t* ms = SGX_CAST(ms_ve_set_lock_delay_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ve_set_lock_delay(ms->ms_mins);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ve_restore_state(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ve_restore_state_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ve_restore_state_t* ms = SGX_CAST(ms_ve_restore_state_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_state = ms->ms_state;
	uint32_t _tmp_sz = ms->ms_sz;
	size_t _len_state = _tmp_sz * sizeof(*_tmp_state);
	char* _in_state = NULL;

	if (sizeof(*_tmp_state) != 0 &&
		(size_t)_tmp_sz > (SIZE_MAX / sizeof(*_tmp_state))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_state, _len_state);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_state != NULL && _len_state != 0) {
		_in_state = (char*)malloc(_len_state);
		if (_in_state == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_state, _tmp_state, _len_state);
	}

	ms->ms_retval = ve_restore_state(_in_state, _tmp_sz);
err:
	if (_in_state) {
		memcpy(_tmp_state, _in_state, _len_state);
		free(_in_state);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[25];
} g_ecall_table = {
	25,
	{
		{(void*)(uintptr_t)sgx_ve_initialize, 0},
		{(void*)(uintptr_t)sgx_ve_initialize_from_header, 0},
		{(void*)(uintptr_t)sgx_ve_load_vault, 0},
		{(void*)(uintptr_t)sgx_ve_get_header_size, 0},
		{(void*)(uintptr_t)sgx_ve_get_header, 0},
		{(void*)(uintptr_t)sgx_ve_get_vault, 0},
		{(void*)(uintptr_t)sgx_ve_get_db_size, 0},
		{(void*)(uintptr_t)sgx_ve_lock, 0},
		{(void*)(uintptr_t)sgx_ve_unlock, 0},
		{(void*)(uintptr_t)sgx_ve_set_master_password, 0},
		{(void*)(uintptr_t)sgx_ve_change_master_password, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_get_count, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_get_info_sizes, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_get_info, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_get_password_size, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_get_password, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_set_info, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_set_password, 0},
		{(void*)(uintptr_t)sgx_ve_accounts_generate_password, 0},
		{(void*)(uintptr_t)sgx_ve_is_valid, 0},
		{(void*)(uintptr_t)sgx_ve_is_locked, 0},
		{(void*)(uintptr_t)sgx_ve_get_state_size, 0},
		{(void*)(uintptr_t)sgx_ve_heartbeat, 0},
		{(void*)(uintptr_t)sgx_ve_set_lock_delay, 0},
		{(void*)(uintptr_t)sgx_ve_restore_state, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][25];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ve_o_process_info(uint64_t* timestamp, uint64_t* pid)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timestamp = sizeof(*timestamp);
	size_t _len_pid = sizeof(*pid);

	ms_ve_o_process_info_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ve_o_process_info_t);
	void *__tmp = NULL;

	void *__tmp_timestamp = NULL;
	void *__tmp_pid = NULL;
	ocalloc_size += (timestamp != NULL && sgx_is_within_enclave(timestamp, _len_timestamp)) ? _len_timestamp : 0;
	ocalloc_size += (pid != NULL && sgx_is_within_enclave(pid, _len_pid)) ? _len_pid : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ve_o_process_info_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ve_o_process_info_t));

	if (timestamp != NULL && sgx_is_within_enclave(timestamp, _len_timestamp)) {
		ms->ms_timestamp = (uint64_t*)__tmp;
		__tmp_timestamp = __tmp;
		memset(__tmp_timestamp, 0, _len_timestamp);
		__tmp = (void *)((size_t)__tmp + _len_timestamp);
	} else if (timestamp == NULL) {
		ms->ms_timestamp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (pid != NULL && sgx_is_within_enclave(pid, _len_pid)) {
		ms->ms_pid = (uint64_t*)__tmp;
		__tmp_pid = __tmp;
		memset(__tmp_pid, 0, _len_pid);
		__tmp = (void *)((size_t)__tmp + _len_pid);
	} else if (pid == NULL) {
		ms->ms_pid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (timestamp) memcpy((void*)timestamp, __tmp_timestamp, _len_timestamp);
		if (pid) memcpy((void*)pid, __tmp_pid, _len_pid);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;
	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) memcpy((void*)cpuinfo, __tmp_cpuinfo, _len_cpuinfo);
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		memcpy(__tmp, waiters, _len_waiters);
		__tmp = (void *)((size_t)__tmp + _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
