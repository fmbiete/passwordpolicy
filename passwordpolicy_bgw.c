/*-------------------------------------------------------------------------
 *
 * passwordpolicy_bgw.c
 *      Background worker for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "passwordpolicy_bgw.h"

#include <time.h>

#include <access/xact.h>
#include <executor/spi.h>
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
#include <pgstat.h>
#if (PG_VERSION_NUM >= 140000)
#include <utils/backend_status.h>
#include <utils/wait_event.h>
#endif
#include <utils/guc.h>
#include <utils/hsearch.h>
#include <utils/memutils.h>
#include <utils/snapmgr.h>
#include <utils/timestamp.h>

#include "passwordpolicy_shmem.h"
#include "passwordpolicy_vars.h"

/* global settings */
static bool PasswordPolicyReloadConfig = false;

/* flags set by signal handlers */
static volatile sig_atomic_t got_sigterm = false;

/* forward declaration private functions */
static void passwordpolicy_populate_users(void);
static void passwordpolicy_sighup(SIGNAL_ARGS);
static void passwordpolicy_sigterm(SIGNAL_ARGS);

/**
 * @brief Main entry point for the background worker
 * @param arg: unused
 * @return void
 */
void PasswordPolicyBgwMain(Datum arg)
{
  int sleep_ms = SECS_PER_MINUTE * 1000;
  MemoryContext PasswordPolicyContext = NULL;

  pqsignal(SIGHUP, passwordpolicy_sighup);
  pqsignal(SIGINT, SIG_IGN);
  pqsignal(SIGTERM, passwordpolicy_sigterm);

  BackgroundWorkerUnblockSignals();

  pgstat_report_appname("passwordpolicy background worker");

  PasswordPolicyContext = AllocSetContextCreate(CurrentMemoryContext, "passwordpolicy context",
                                                ALLOCSET_DEFAULT_MINSIZE, ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);

  ereport(LOG, (errmsg("passwordpolicy: background worker started")));

  MemoryContextSwitchTo(PasswordPolicyContext);

  /* Connect to postgres as main user */
  BackgroundWorkerInitializeConnection("postgres", NULL, 0);
  /* Disable paralle query */
  SetConfigOption("max_parallel_workers_per_gather", "0", PGC_USERSET, PGC_S_OVERRIDE);

  /* initialize account list */
  passwordpolicy_populate_users();

  while (1)
  {
    int rc;

    CHECK_FOR_INTERRUPTS();

    if (PasswordPolicyReloadConfig)
    {
      ProcessConfigFile(PGC_SIGHUP);
      PasswordPolicyReloadConfig = false;
    }

    /* refresh account list */
    passwordpolicy_populate_users();

    /* shutdown if requested */
    if (got_sigterm)
    {
      break;
    }

    rc = WaitLatch(&MyProc->procLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH, sleep_ms,
                   PG_WAIT_EXTENSION);
    if (rc & WL_POSTMASTER_DEATH)
      proc_exit(1);

    ResetLatch(&MyProc->procLatch);
  }

  MemoryContextReset(PasswordPolicyContext);

  ereport(LOG, (errmsg("passwordpolicy: background worker shutting down")));

  proc_exit(0);
}

/* private functions */

/**
 * @brief Signal handler for SIGHUP
 * @param signal_arg: signal number
 * @return void
 */
static void
passwordpolicy_sigterm(SIGNAL_ARGS)
{
  got_sigterm = true;
  if (MyProc != NULL)
  {
    SetLatch(&MyProc->procLatch);
  }
}

/**
 * @brief Signal handler for SIGTERM
 * @param signal_arg: signal number
 * @return void
 */
static void
passwordpolicy_sighup(SIGNAL_ARGS)
{
  PasswordPolicyReloadConfig = true;
  if (MyProc != NULL)
  {
    SetLatch(&MyProc->procLatch);
  }
}

void passwordpolicy_populate_users(void)
{
  bool found;
  int ret, i;
  TupleDesc tupdesc;
  SPITupleTable *tuptable;
  StringInfoData buf;
  HASH_SEQ_STATUS hash_seq;
  PasswordPolicyAccount *entry;
  PasswordPolicyAccountKey key;

  if (!passwordpolicy_shmem_check())
    return;

  SetCurrentStatementStartTimestamp();
  StartTransactionCommand();
  SPI_connect();
  PushActiveSnapshot(GetTransactionSnapshot());

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy checking extension");

  ret = SPI_execute("SELECT 1 FROM pg_extension WHERE extname = 'passwordpolicy'", true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to check if extension is installed")));
    goto error;
  }

  if (SPI_processed == 0)
  {
    ereport(INFO, (errmsg("passwordpolicy: extension is not installed, skipping account auth checks")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy soft-deleting accounts");

  /* Mark all the accounts for deletion with shared lock */
  LWLockAcquire(passwordpolicy_shm->lock, LW_SHARED);
  hash_seq_init(&hash_seq, passwordpolicy_hash_accounts);
  while ((entry = (PasswordPolicyAccount *)hash_seq_search(&hash_seq)) != NULL)
  {
    entry->to_delete = true;
  }
  LWLockRelease(passwordpolicy_shm->lock);

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy reading accounts");
  initStringInfo(&buf);

  if (guc_passwordpolicy_lock_all_accounts)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: reading accounts from pg_user")));
    appendStringInfo(&buf, "SELECT usename FROM pg_user ORDER BY usename");
  }
  else
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: reading accounts from passwordpolicy.accounts_lockable")));
    appendStringInfo(&buf, "SELECT usename FROM passwordpolicy.accounts_lockable ORDER BY usename");
  }

  ret = SPI_execute(buf.data, true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to get list of accounts to consider for locking")));
    goto error;
  }

  tupdesc = SPI_tuptable->tupdesc;
  tuptable = SPI_tuptable;

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy adding accounts");

  /* Add accounts: we don't need an exclusive lock */
  LWLockAcquire(passwordpolicy_shm->lock, LW_SHARED);
  for (i = 0; i < SPI_processed; i++)
  {
    const char *username = SPI_getvalue(tuptable->vals[i], tupdesc, 1);
    if (username != NULL)
    {
      entry = (PasswordPolicyAccount *)hash_search(passwordpolicy_hash_accounts, username, HASH_ENTER_NULL, &found);
      if (found)
      {
        entry->to_delete = false;
      }
      else
      {
        if (entry == NULL)
        {
          ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY),
                          errmsg("passwordpolicy: not enough shared memory to add accounts to auth lock"),
                          errhint("increase the value of passwordpolicy.max_number_accounts")));
        }
        else
        {
          ereport(DEBUG3, (errmsg("passwordpolicy: adding account '%s' to auth lock", username)));
          pg_atomic_init_u64(&(entry->failures), 0);
          pg_atomic_init_u64(&(entry->last_failure), 0);
          entry->to_delete = false;
          /* add key the last to avoid reading uninitialized values */
          strncpy(entry->key, username, NAMEDATALEN);
        }
      }
    } /* if usename != NULL*/
  } /* for select */
  LWLockRelease(passwordpolicy_shm->lock);

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy hard-deleting accounts");
  /* delete entries not present: We need an exclusive lock, this will lock the listing of accounts, but won't impact logins */
  LWLockAcquire(passwordpolicy_shm->lock, LW_EXCLUSIVE);
  hash_seq_init(&hash_seq, passwordpolicy_hash_accounts);
  while ((entry = (PasswordPolicyAccount *)hash_seq_search(&hash_seq)) != NULL)
  {
    if (entry->to_delete)
    {
      strncpy(key, entry->key, NAMEDATALEN);

      hash_search(passwordpolicy_hash_accounts, &key, HASH_REMOVE, &found);
      if (found)
      {
        ereport(DEBUG3, (errmsg("passwordpolicy: removed account '%s' from auth lock", key)));
      }
    }
  }
  LWLockRelease(passwordpolicy_shm->lock);

error:
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}
