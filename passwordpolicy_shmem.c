/*-------------------------------------------------------------------------
 *
 * passwordpolicy_shmem.c
 *      Functions to manage shared memory
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "passwordpolicy_shmem.h"

#include <miscadmin.h>
#include <storage/pg_shmem.h>
#include <storage/shmem.h>
#include <utils/hsearch.h>
#include <utils/timestamp.h>

#include "passwordpolicy_vars.h"

/* Private functions forward declaration */
Size passwordpolicy_memsize(void);

bool passwordpolicy_shmem_check(void)
{
  return passwordpolicy_shm && passwordpolicy_hash_accounts &&
         pg_atomic_unlocked_test_flag(&(passwordpolicy_shm->flag_shutdown));
}

/**
 * @brief Request shared memory space
 * @param void
 * @return void
 */
void passwordpolicy_shmem_request(void)
{
#if (PG_VERSION_NUM >= 150000)
  if (prev_shmem_request_hook)
    prev_shmem_request_hook();
#endif

  RequestAddinShmemSpace(MAXALIGN(sizeof(PasswordPolicyShm)));
  RequestNamedLWLockTranche("passwordpolicy", 1);
}

/**
 * @brief SHMEM startup hook - Initialize SHMEM structure
 * @param void
 * @return void
 */
void passwordpolicy_shmem_startup(void)
{
  bool found;
  HASHCTL info;

  // Execute other hooks
  if (prev_shmem_startup_hook)
    prev_shmem_startup_hook();

  /* reset in case this is a restart within the postmaster */
  passwordpolicy_shm = NULL;
  passwordpolicy_hash_accounts = NULL;

  LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

  passwordpolicy_shm = ShmemInitStruct("passwordpolicy", sizeof(PasswordPolicyShm), &found);
  if (!found)
  {
    passwordpolicy_shm->lock = &(GetNamedLWLockTranche("passwordpolicy"))->lock;
    pg_atomic_init_flag(&(passwordpolicy_shm->flag_shutdown));
  }

  info.keysize = sizeof(PasswordPolicyAccountKey);
  info.entrysize = sizeof(PasswordPolicyAccount);
  passwordpolicy_hash_accounts = ShmemInitHash("passwordpolicy hash accounts",
                                               guc_passwordpolicy_max_num_accounts,
                                               guc_passwordpolicy_max_num_accounts,
                                               &info,
#if (PG_VERSION_NUM >= 140000)
                                               HASH_ELEM | HASH_STRINGS);
#else
                                               HASH_ELEM);
#endif

  LWLockRelease(AddinShmemInitLock);

  if (!IsUnderPostmaster)
    on_shmem_exit(passwordpolicy_shmem_shutdown, (Datum)0);

  if (!found)
    ereport(LOG, (errmsg("passwordpolicy: shmem initialized")));
}

/**
 * @brief SHMEM shutdown hook
 * @param code: code
 * @param arg: arg
 * @return void
 */
void passwordpolicy_shmem_shutdown(int code, Datum arg)
{
  /* Safety check */
  if (!passwordpolicy_shm || !passwordpolicy_hash_accounts)
    return;

  pg_atomic_test_set_flag(&(passwordpolicy_shm->flag_shutdown));
}

/* Private functions */
Size passwordpolicy_memsize(void)
{
  Size size;

  size = MAXALIGN(sizeof(PasswordPolicyShm));
  size = add_size(size, hash_estimate_size(guc_passwordpolicy_max_num_accounts, sizeof(PasswordPolicyAccount)));

  return size;
}