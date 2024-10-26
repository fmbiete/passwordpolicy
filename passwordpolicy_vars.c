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

// Guc
int guc_passwordpolicy_max_num_accounts = 100;      // Default: 100
int guc_passwordpolicy_min_length = 15;             // Default: 15
int guc_passwordpolicy_min_spc_char = 1;            // Default: 1
int guc_passwordpolicy_min_number_char = 1;         // Default: 1
int guc_passwordpolicy_min_upper_char = 1;          // Default: 1
int guc_passwordpolicy_min_lower_char = 1;          // Default: 1
bool guc_passwordpolicy_require_validuntil = false; // Default: false
bool guc_passwordpolicy_enable_dict_check = true;   // Default: true
int guc_passwordpolicy_lock_after = 5;              // Default: 5
bool guc_passwordpolicy_lock_all_accounts = true;   // Default: true
int guc_passwordpolicy_login_failure_delay = 5;     // Default: 5 seconds

// Hooks
check_password_hook_type prev_check_password_hook = NULL;
ClientAuthentication_hook_type prev_client_authentication_hook = NULL;

// Shared memory
PasswordPolicyShm *passwordpolicy_shm = NULL;
HTAB *passwordpolicy_hash_accounts = NULL;

// Shared memory hook
shmem_startup_hook_type prev_shmem_startup_hook = NULL;
#if (PG_VERSION_NUM >= 150000)
shmem_request_hook_type prev_shmem_request_hook = NULL;
#endif
