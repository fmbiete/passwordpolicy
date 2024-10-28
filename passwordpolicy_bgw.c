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

#include <access/xact.h>
/* these are always necessary for a bgworker */
#include <miscadmin.h>
#include <pgstat.h>
#include <postmaster/bgworker.h>
#include <storage/ipc.h>
#include <storage/latch.h>
#include <storage/lwlock.h>
#include <storage/proc.h>
#include <storage/shm_mq.h>
#include <storage/shm_toc.h>
#include <storage/shmem.h>
#if (PG_VERSION_NUM >= 140000)
#include <utils/backend_status.h>
#include <utils/wait_event.h>
#endif
#include <utils/guc.h>
#include <utils/memutils.h>

#include "passwordpolicy_hash_accounts.h"
#include "passwordpolicy_hash_history.h"
#include "passwordpolicy_shmem.h"
#include "passwordpolicy_vars.h"

/* global settings */
static bool PasswordPolicyReloadConfig = false;

/* flags set by signal handlers */
static volatile sig_atomic_t got_sigterm = false;

/* forward declaration private functions */
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

  passwordpolicy_hash_accounts_load();

  passwordpolicy_hash_history_load();

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
    passwordpolicy_hash_accounts_load();

    passwordpolicy_hash_history_save();

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
