/*-------------------------------------------------------------------------
 *
 * passwordpolicy.c
 *
 * Copyright (c) 2023-2024, Francisco Miguel Biete Banon
 * Copyright (c) 2018-2023, indrajit
 * Copyright (c) 2009-2017, PostgreSQL Global Development Group
 * Based in the initial work of Laurenz Albe <laurenz.albe@wien.gv.at>
 *
 *-------------------------------------------------------------------------
 */

#include <postgres.h>

#include <libpq/auth.h>
/* these are always necessary for a bgworker */
#include <miscadmin.h>
#include <postmaster/bgworker.h>
#include <storage/ipc.h>
#include <storage/latch.h>
#include <storage/lwlock.h>
#include <storage/proc.h>
#include <storage/shm_mq.h>
#include <storage/shm_toc.h>
#include <storage/shmem.h>

#include <utils/guc.h>

PG_MODULE_MAGIC;

#include "passwordpolicy.h"
#include "passwordpolicy_auth.h"
#include "passwordpolicy_bgw.h"
#include "passwordpolicy_check.h"
#include "passwordpolicy_shmem.h"
#include "passwordpolicy_vars.h"

/*
 * Module initialization function
 */
void _PG_init(void)
{
  BackgroundWorker worker;

  if (!process_shared_preload_libraries_in_progress)
  {
    ereport(ERROR, (
                       errmsg("passwordpolicy can only be loaded via shared_preload_libraries"),
                       errhint("Add passwordpolicy to the shared_preload_libraries configuration variable in postgresql.conf.")));
  }

  /* Password checks */
  DefineCustomIntVariable(
      "password_policy.min_password_len",
      "Minimum password length.",
      NULL, &guc_passwordpolicy_min_length, 15, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy.min_special_chars",
      "Minimum number of special characters.",
      NULL, &guc_passwordpolicy_min_spc_char, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy.min_numbers",
      "Minimum number of numeric characters.",
      NULL, &guc_passwordpolicy_min_number_char, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy.min_uppercase_letter",
      "Minimum number of upper case letters.",
      NULL, &guc_passwordpolicy_min_upper_char, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy.min_lowercase_letter",
      "Minimum number of lower case letters.",
      NULL, &guc_passwordpolicy_min_lower_char, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "password_policy.enable_dictionary_check",
      "Enable check against dictionary",
      NULL, &guc_passwordpolicy_enable_dict_check, false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "password_policy.require_validuntil",
      "Require valid until when changing or setting a password",
      NULL, &guc_passwordpolicy_require_validuntil, false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Account Soft-Lock */
  DefineCustomIntVariable(
      "password_policy_lock.max_number_accounts",
      "Maximum number of accounts to consider for soft-locking",
      NULL, &guc_passwordpolicy_lock_max_num_accounts, 100, 1, INT_MAX,
      PGC_POSTMASTER, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy_lock.number_failures",
      "Number of login failures before soft-locking the account",
      NULL, &guc_passwordpolicy_lock_after, 5, 1, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "password_policy_lock.include_all",
      "Consider all the accounts in the system, or only those in the passwordpolicy.accounts_lockable table",
      NULL, &guc_passwordpolicy_lock_all_accounts, false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy_lock.failure_delay",
      "Introduce this delay in seconds after a failed login, if the acount is in the included list",
      NULL, &guc_passwordpolicy_lock_failure_delay, 5, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "password_policy_lock.auto_unlock",
      "Automatically soft-unlock the accounts",
      NULL, &guc_passwordpolicy_lock_auto_unlock, true,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy_lock.auto_unlock_after",
      "Automatically soft-unlock the account after this number of seconds since the last failed login",
      NULL, &guc_passwordpolicy_lock_auto_unlock_after, 0, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Password History */
  DefineCustomIntVariable(
      "password_policy_history.max_number_accounts",
      "Maximum number of accounts with saved histroy",
      NULL, &guc_passwordpolicy_history_max_num_accounts, 100, 1, INT_MAX,
      PGC_POSTMASTER, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "password_policy_history.max_password_history",
      "Password history entries to keep",
      NULL, &guc_passwordpolicy_history_max_num_entries, 5, 1, INT_MAX,
      PGC_POSTMASTER, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  EmitWarningsOnPlaceholders("pgauditlogtofile");

  /* background worker */
  MemSet(&worker, 0, sizeof(BackgroundWorker));
  worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
  worker.bgw_start_time = BgWorkerStart_ConsistentState;
  worker.bgw_restart_time = 1;
  worker.bgw_main_arg = Int32GetDatum(0);
  worker.bgw_notify_pid = 0;
  sprintf(worker.bgw_library_name, "passwordpolicy");
  sprintf(worker.bgw_function_name, "PasswordPolicyBgwMain");
  snprintf(worker.bgw_name, BGW_MAXLEN, "passwordpolicy launcher");

  RegisterBackgroundWorker(&worker);

/* backend hooks */
#if (PG_VERSION_NUM >= 150000)
  prev_shmem_request_hook = shmem_request_hook;
  shmem_request_hook = passwordpolicy_shmem_request;
#else
  /* call the function hook manually */
  passwordpolicy_shmem_request();
#endif

  prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = passwordpolicy_shmem_startup;
  prev_check_password_hook = check_password_hook;
  check_password_hook = passwordpolicy_check_password;
  prev_client_authentication_hook = ClientAuthentication_hook;
  ClientAuthentication_hook = passwordpolicy_client_authentication;
}

void _PG_fini(void)
{
  shmem_startup_hook = prev_shmem_startup_hook;
  check_password_hook = prev_check_password_hook;
  ClientAuthentication_hook = prev_client_authentication_hook;
}
