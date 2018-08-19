#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ve_initialize();
int ve_initialize_from_header(unsigned char* header, uint16_t len);
int ve_load_vault(unsigned char* edata);
int ve_get_header_size(uint16_t* sz);
int ve_get_header(unsigned char* header, uint16_t len);
int ve_get_vault(unsigned char* edata, uint32_t len);
uint32_t ve_get_db_size();
void ve_lock();
int ve_unlock(char* password);
int ve_set_master_password(char* password);
int ve_change_master_password(char* oldpass, char* newpass);
int ve_accounts_get_count(uint32_t* count);
int ve_accounts_get_info_sizes(uint32_t idx, uint16_t* mbname_sz, uint16_t* mblogin_sz, uint16_t* mburl_sz);
int ve_accounts_get_info(uint32_t idx, char* mbname, uint16_t mbname_sz, char* mblogin, uint16_t mblogin_sz, char* mburl, uint16_t mburl_sz);
int ve_accounts_get_password_size(uint32_t idx, uint16_t* mbpass_sz);
int ve_accounts_get_password(uint32_t idx, char* mbpass, uint16_t mbpass_sz);
int ve_accounts_set_info(uint32_t idx, char* mbname, uint16_t mbname_len, char* mblogin, uint16_t mblogin_len, char* mburl, uint16_t mburl_len);
int ve_accounts_set_password(uint32_t idx, char* mbpass, uint16_t mbpass_len);
int ve_accounts_generate_password(uint16_t length, uint16_t flags, char* cpass);
int ve_is_valid();
int ve_is_locked();
uint32_t ve_get_state_size();
int ve_heartbeat(char* state, uint32_t sz);
void ve_set_lock_delay(uint16_t mins);
int ve_restore_state(char* state, uint32_t sz);

sgx_status_t SGX_CDECL ve_o_process_info(uint64_t* timestamp, uint64_t* pid);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
