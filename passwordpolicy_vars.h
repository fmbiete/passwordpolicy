/*-------------------------------------------------------------------------
 *
 * passwordpolicy_vars.h
 *      Global variables for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_VARS_H_
#define _PASSWORDPOLICY_VARS_H_

#include <postgres.h>
#include <commands/user.h>
#include <datatype/timestamp.h>
#include <libpq/auth.h>
#include <miscadmin.h>
#include <pgtime.h>
#include <port/atomics.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <utils/hsearch.h>

// Guc
extern int guc_passwordpolicy_max_num_accounts;
extern int guc_passwordpolicy_min_length;
extern int guc_passwordpolicy_min_spc_char;
extern int guc_passwordpolicy_min_number_char;
extern int guc_passwordpolicy_min_upper_char;
extern int guc_passwordpolicy_min_lower_char;
extern bool guc_passwordpolicy_require_validuntil;
extern bool guc_passwordpolicy_enable_dict_check;
extern int guc_passwordpolicy_lock_after;
extern bool guc_passwordpolicy_lock_all_accounts;
extern int guc_passwordpolicy_login_failure_delay;
extern bool guc_passwordpolicy_lock_auto_unlock;
extern int guc_passwordpolicy_lock_auto_unlock_after;

// Hooks
extern check_password_hook_type prev_check_password_hook;
extern ClientAuthentication_hook_type prev_client_authentication_hook;

// Shared Memory types
typedef char PasswordPolicyAccountKey[NAMEDATALEN + 1];
typedef struct PasswordPolicyAccount
{
  PasswordPolicyAccountKey key; /* hash key of entry - MUST BE FIRST */
  pg_atomic_uint64 failures;
  pg_atomic_uint64 last_failure; /* typedef int64 pg_time_t */
  bool to_delete;
} PasswordPolicyAccount;

typedef struct PasswordPolicyShm
{
  LWLock *lock;
  pg_atomic_flag flag_shutdown;
} PasswordPolicyShm;

// Shared Memory
extern PasswordPolicyShm *passwordpolicy_shm;
extern HTAB *passwordpolicy_hash_accounts;

// Shared Memory - Hook
extern shmem_startup_hook_type prev_shmem_startup_hook;
#if (PG_VERSION_NUM >= 150000)
extern shmem_request_hook_type prev_shmem_request_hook;
#endif

#endif
