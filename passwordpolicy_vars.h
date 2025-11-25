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
#include <common/sha2.h>
#include <datatype/timestamp.h>
#include <libpq/auth.h>
#include <miscadmin.h>
#include <pgtime.h>
#include <port/atomics.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <utils/hsearch.h>

// GUC Password checks
extern bool guc_passwordpolicy_enable_dict_check;
extern int guc_passwordpolicy_min_length;
extern int guc_passwordpolicy_min_lower_char;
extern int guc_passwordpolicy_min_number_char;
extern int guc_passwordpolicy_min_spc_char;
extern int guc_passwordpolicy_min_upper_char;
extern bool guc_passwordpolicy_require_validuntil;
// GUC Auth Soft-lock
extern int guc_passwordpolicy_lock_after;
extern bool guc_passwordpolicy_lock_all_accounts;
extern bool guc_passwordpolicy_lock_auto_unlock;
extern int guc_passwordpolicy_lock_auto_unlock_after;
extern int guc_passwordpolicy_lock_failure_delay;
extern int guc_passwordpolicy_lock_max_num_accounts;
// GUC Password History
extern int guc_passwordpolicy_history_max_num_accounts;
extern int guc_passwordpolicy_history_max_num_entries;

// Hooks
extern check_password_hook_type passwordpolicy_prev_check_password_hook;
extern ClientAuthentication_hook_type passwordpolicy_prev_client_authentication_hook;

// Shared Memory types
typedef char PasswordPolicyAccountKey[NAMEDATALEN + 1];
typedef struct PasswordPolicyAccount
{
  PasswordPolicyAccountKey key;
  pg_atomic_uint64 failures;
  pg_atomic_uint64 last_failure; /* typedef int64 pg_time_t */
  pg_atomic_uint64 deleted;
} PasswordPolicyAccount;

typedef struct PasswordPolicyHistoryHash
{
  char password_hash[PG_SHA256_DIGEST_STRING_LENGTH];
  TimestampTz changed_at;
} PasswordPolicyHistoryHash;

typedef struct PasswordPolicyHistory
{
  PasswordPolicyAccountKey key;
  PasswordPolicyHistoryHash *hashes;
} PasswordPolicyHistory;

typedef struct PasswordPolicyShm
{
  LWLock *lock;
  pg_atomic_flag flag_shutdown;
} PasswordPolicyShm;

// Shared Memory
extern PasswordPolicyShm *passwordpolicy_shm;
extern HTAB *passwordpolicy_hash_accounts;
extern HTAB *passwordpolicy_hash_history;
extern TimestampTz passwordpolicy_hash_history_last_save;
extern LWLock *passwordpolicy_lock_accounts;
extern LWLock *passwordpolicy_lock_history;

// Shared Memory - Hook
extern shmem_startup_hook_type passwordpolicy_prev_shmem_startup_hook;
#if (PG_VERSION_NUM >= 150000)
extern shmem_request_hook_type passwordpolicy_prev_shmem_request_hook;
#endif

#endif
