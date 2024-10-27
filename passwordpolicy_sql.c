/*-------------------------------------------------------------------------
 *
 * passwordpolicy_sql.c
 *      SQL exported functions for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_sql.h"

#include <funcapi.h>
#include <nodes/execnodes.h>
#include <utils/hsearch.h>
#include <utils/timestamp.h>

#include "passwordpolicy_shmem.h"
#include "passwordpolicy_vars.h"

#define PASSWORD_POLICY_SQL_LOCKED_NUMC 3

/* We don't need to return on error on functions */

PG_FUNCTION_INFO_V1(account_locked_reset);
Datum account_locked_reset(PG_FUNCTION_ARGS)
{
  bool found;
  char *usename;
  PasswordPolicyAccount *entry;

  passwordpolicy_shmem_check();

  if (!superuser())
    ereport(ERROR, (errmsg("only superuser can execute this function")));

  if (PG_NARGS() != 1)
    ereport(ERROR, (errmsg("missing function argument usename")));

  usename = PG_GETARG_CSTRING(0);

  entry = (PasswordPolicyAccount *)hash_search(passwordpolicy_hash_accounts, usename, HASH_FIND, &found);
  if (found)
  {
    ereport(DEBUG3, (errmsg("usename '%s' failures manually reset", usename)));
    pg_atomic_write_u64(&(entry->failures), 0);
  }
  else
  {
    ereport(ERROR, (errmsg("usename '%s' not found in lockable list", usename)));
  }

  PG_RETURN_INT32(0);
}

PG_FUNCTION_INFO_V1(accounts_locked);
Datum accounts_locked(PG_FUNCTION_ARGS)
{
  ReturnSetInfo *rsinfo;
  TupleDesc tupdesc;
  Tuplestorestate *tupstore;
  MemoryContext per_query_ctx;
  MemoryContext oldcontext;
  HASH_SEQ_STATUS hash_seq;
  PasswordPolicyAccount *entry;

  passwordpolicy_shmem_check();

  if (!superuser())
    ereport(ERROR, (errmsg("only superuser can execute this function")));

  rsinfo = (ReturnSetInfo *)fcinfo->resultinfo;

  if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
    ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("context doesn't support return set")));

  if (!(rsinfo->allowedModes & SFRM_Materialize))
    ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED), errmsg("context doesn't support materialize mode")));

  per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
  oldcontext = MemoryContextSwitchTo(per_query_ctx);

  /* Build a tuple descriptor for our result type */
  if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
    elog(ERROR, "return type must be a row type");

  tupstore = tuplestore_begin_heap(true, false, work_mem);
  rsinfo->returnMode = SFRM_Materialize;
  rsinfo->setResult = tupstore;
  rsinfo->setDesc = tupdesc;

  MemoryContextSwitchTo(oldcontext);

  LWLockAcquire(passwordpolicy_shm->lock, LW_SHARED);

  hash_seq_init(&hash_seq, passwordpolicy_hash_accounts);
  while ((entry = (PasswordPolicyAccount *)hash_seq_search(&hash_seq)) != NULL)
  {
    Datum values[PASSWORD_POLICY_SQL_LOCKED_NUMC];
    bool nulls[PASSWORD_POLICY_SQL_LOCKED_NUMC];
    TimestampTz last_failure;

    memset(values, 0, sizeof(values));
    memset(nulls, 0, sizeof(nulls));

    values[0] = CStringGetDatum(entry->key);
    values[1] = Int64GetDatum(pg_atomic_read_u64(&(entry->failures)));
    last_failure = pg_atomic_read_u64(&(entry->last_failure));
    ereport(DEBUG3, (errmsg("usename '%s' %ld", entry->key, last_failure)));
    if (last_failure > 0)
      values[2] = TimestampTzGetDatum(last_failure);
    else
      nulls[2] = true;

    tuplestore_putvalues(tupstore, tupdesc, values, nulls);
  }

  LWLockRelease(passwordpolicy_shm->lock);

  PG_RETURN_INT32(0);
}
