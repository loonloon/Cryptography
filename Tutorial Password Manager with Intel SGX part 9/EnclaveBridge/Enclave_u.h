#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_CDECL, ve_o_process_info, (uint64_t* timestamp, uint64_t* pid));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t ve_initialize(sgx_enclave_id_t eid, int* retval);
sgx_status_t ve_initialize_from_header(sgx_enclave_id_t eid, int* retval, unsigned char* header, uint16_t len);
sgx_status_t ve_load_vault(sgx_enclave_id_t eid, int* retval, unsigned char* edata);
sgx_status_t ve_get_header_size(sgx_enclave_id_t eid, int* retval, uint16_t* sz);
sgx_status_t ve_get_header(sgx_enclave_id_t eid, int* retval, unsigned char* header, uint16_t len);
sgx_status_t ve_get_vault(sgx_enclave_id_t eid, int* retval, unsigned char* edata, uint32_t len);
sgx_status_t ve_get_db_size(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t ve_lock(sgx_enclave_id_t eid);
sgx_status_t ve_unlock(sgx_enclave_id_t eid, int* retval, char* password);
sgx_status_t ve_set_master_password(sgx_enclave_id_t eid, int* retval, char* password);
sgx_status_t ve_change_master_password(sgx_enclave_id_t eid, int* retval, char* oldpass, char* newpass);
sgx_status_t ve_accounts_get_count(sgx_enclave_id_t eid, int* retval, uint32_t* count);
sgx_status_t ve_accounts_get_info_sizes(sgx_enclave_id_t eid, int* retval, uint32_t idx, uint16_t* mbname_sz, uint16_t* mblogin_sz, uint16_t* mburl_sz);
sgx_status_t ve_accounts_get_info(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbname, uint16_t mbname_sz, char* mblogin, uint16_t mblogin_sz, char* mburl, uint16_t mburl_sz);
sgx_status_t ve_accounts_get_password_size(sgx_enclave_id_t eid, int* retval, uint32_t idx, uint16_t* mbpass_sz);
sgx_status_t ve_accounts_get_password(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbpass, uint16_t mbpass_sz);
sgx_status_t ve_accounts_set_info(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbname, uint16_t mbname_len, char* mblogin, uint16_t mblogin_len, char* mburl, uint16_t mburl_len);
sgx_status_t ve_accounts_set_password(sgx_enclave_id_t eid, int* retval, uint32_t idx, char* mbpass, uint16_t mbpass_len);
sgx_status_t ve_accounts_generate_password(sgx_enclave_id_t eid, int* retval, uint16_t length, uint16_t flags, char* cpass);
sgx_status_t ve_is_valid(sgx_enclave_id_t eid, int* retval);
sgx_status_t ve_is_locked(sgx_enclave_id_t eid, int* retval);
sgx_status_t ve_get_state_size(sgx_enclave_id_t eid, uint32_t* retval);
sgx_status_t ve_heartbeat(sgx_enclave_id_t eid, int* retval, char* state, uint32_t sz);
sgx_status_t ve_set_lock_delay(sgx_enclave_id_t eid, uint16_t mins);
sgx_status_t ve_restore_state(sgx_enclave_id_t eid, int* retval, char* state, uint32_t sz);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
