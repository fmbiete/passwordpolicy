/*-------------------------------------------------------------------------
 *
 * passwordpolicy_vars.c
 *      Global variables for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "passwordpolicy_vars.h"

// GUC Password checks
bool guc_passwordpolicy_enable_dict_check = true;   // Default: true
int guc_passwordpolicy_min_length = 15;             // Default: 15
int guc_passwordpolicy_min_spc_char = 1;            // Default: 1
int guc_passwordpolicy_min_number_char = 1;         // Default: 1
int guc_passwordpolicy_min_upper_char = 1;          // Default: 1
int guc_passwordpolicy_min_lower_char = 1;          // Default: 1
bool guc_passwordpolicy_require_validuntil = false; // Default: false
// GUC Auth Soft-lock
int guc_passwordpolicy_lock_after = 5;              // Default: 5
bool guc_passwordpolicy_lock_all_accounts = true;   // Default: true
bool guc_passwordpolicy_lock_auto_unlock = true;    // Default: true
int guc_passwordpolicy_lock_auto_unlock_after = 0;  // Default: 0 seconds (immediate)
int guc_passwordpolicy_lock_failure_delay = 5;      // Default: 5 seconds
int guc_passwordpolicy_lock_max_num_accounts = 100; // Default: 100
// GUC Password History
int guc_passwordpolicy_history_max_num_accounts = 100; // Default: 100
int guc_passwordpolicy_history_max_num_entries = 5;    // Default: 5

// Hooks
check_password_hook_type prev_check_password_hook = NULL;
ClientAuthentication_hook_type prev_client_authentication_hook = NULL;

// Shared memory
PasswordPolicyShm *passwordpolicy_shm = NULL;
HTAB *passwordpolicy_hash_accounts = NULL;
HTAB *passwordpolicy_hash_history = NULL;
LWLock *passwordpolicy_lock_accounts = NULL;
LWLock *passwordpolicy_lock_history = NULL;

// Shared memory hook
shmem_startup_hook_type prev_shmem_startup_hook = NULL;
#if (PG_VERSION_NUM >= 150000)
shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
