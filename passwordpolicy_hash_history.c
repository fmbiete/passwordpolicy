/*-------------------------------------------------------------------------
 *
 * passwordpolicy_hash_history.h
 *      Hash table for Password History
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_hash_history.h"

#include <access/xact.h>
#include <executor/spi.h>
#include <pgstat.h>
#include <storage/shmem.h>
#include <utils/builtins.h>
#include <utils/hsearch.h>
#include <utils/snapmgr.h>

#include "passwordpolicy_vars.h"

void passwordpolicy_hash_history_add(const char *username, const char *password_hash, const TimestampTz changed_at)
{
  bool found;
  int i;
  PasswordPolicyHistory *entry;
  PasswordPolicyHistoryHash *oldest_hash;

  if (username == NULL)
    return;

  entry = (PasswordPolicyHistory *)hash_search(passwordpolicy_hash_history, username, HASH_ENTER_NULL, &found);
  if (entry == NULL)
  {
    ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY),
                    errmsg("passwordpolicy: not enough shared memory to add password history entry"),
                    errhint("increase the value of password_policy_history.max_number_accounts")));
    return;
  }

  if (!found)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' without password history", username)));
    strncpy(entry->key, username, NAMEDATALEN);
    entry->hashes = (PasswordPolicyHistoryHash *)ShmemAlloc(mul_size(guc_passwordpolicy_history_max_num_entries, sizeof(PasswordPolicyHistoryHash)));
    if (!entry->hashes)
      return;
    MemSet(entry->hashes, 0, mul_size(guc_passwordpolicy_history_max_num_entries, sizeof(PasswordPolicyHistoryHash)));
  }

  oldest_hash = NULL;
  for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
  {
    if (entry->hashes[i].changed_at == 0)
    {
      entry->hashes[i].changed_at = changed_at;
      strcpy(entry->hashes[i].password_hash, password_hash);
      ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' password history set in '%d' '%ld'",
                              username, i, changed_at)));
      return;
    }
    else
    {
      if (oldest_hash == NULL || oldest_hash->changed_at > entry->hashes[i].changed_at)
        oldest_hash = &(entry->hashes[i]);
    }
  }

  if (oldest_hash)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' password history overwritting '%s' '%ld'",
                            username, oldest_hash->password_hash, oldest_hash->changed_at)));
    oldest_hash->changed_at = changed_at;
    strcpy(oldest_hash->password_hash, password_hash);
  }
}

bool passwordpolicy_hash_history_exists(const char *username, const char *password_hash)
{
  bool found;
  int i;
  PasswordPolicyHistory *entry;

  if (username == NULL)
    return false;

  entry = (PasswordPolicyHistory *)hash_search(passwordpolicy_hash_history, username, HASH_FIND, &found);
  if (!found)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' without password history", username)));
    return false;
  }

  ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' with password history", username)));

  for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
  {
    if (entry->hashes[i].changed_at != 0)
    {
      if (strcmp(password_hash, entry->hashes[i].password_hash) == 0)
        return true;
    }
  }

  ereport(DEBUG3, (errmsg("passwordpolicy: password hash for account '%s' doesn't exist", username)));

  return false;
}

void passwordpolicy_hash_history_init(void)
{
  HASHCTL info;

  info.keysize = sizeof(PasswordPolicyAccountKey);
  info.entrysize = sizeof(PasswordPolicyHistory);
  passwordpolicy_hash_history = ShmemInitHash("passwordpolicy hash history",
                                              guc_passwordpolicy_history_max_num_accounts,
                                              guc_passwordpolicy_history_max_num_accounts,
                                              &info,
#if (PG_VERSION_NUM >= 140000)
                                              HASH_ELEM | HASH_STRINGS
#else
                                              HASH_ELEM
#endif
  );
}

void passwordpolicy_hash_history_load(void)
{
  bool isnull;
  char *query;
  Datum params[1];
  int ret, i;
  TupleDesc tupdesc;
  SPIPlanPtr plan;
  SPITupleTable *tuptable;

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
    ereport(INFO, (errmsg("passwordpolicy: extension is not installed, skipping password history")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy reading accounts");

  query = "WITH ranked_history AS ("
          "  SELECT usename, password_hash, changed_at, "
          "         ROW_NUMBER() OVER (PARTITION BY usename ORDER BY changed_at DESC) AS row_num "
          "  FROM passwordpolicy.accounts_password_history "
          ") "
          "SELECT usename, password_hash, changed_at "
          "FROM ranked_history "
          "WHERE row_num <= $1;";

  plan = SPI_prepare(query, 1, (Oid[]){INT4OID});
  if (plan == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history query")));
    goto error;
  }

  params[0] = Int32GetDatum(guc_passwordpolicy_history_max_num_entries);
  ret = SPI_execute_plan(plan, params, NULL, true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to read password history")));
    goto error;
  }

  tupdesc = SPI_tuptable->tupdesc;
  tuptable = SPI_tuptable;

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy loading history");

  LWLockAcquire(passwordpolicy_lock_history, LW_EXCLUSIVE);
  for (i = 0; i < SPI_processed; i++)
  {
    passwordpolicy_hash_history_add(SPI_getvalue(tuptable->vals[i], tupdesc, 1),
                                    SPI_getvalue(tuptable->vals[i], tupdesc, 2),
                                    DatumGetTimestampTz(SPI_getbinval(tuptable->vals[i], tupdesc, 3, &isnull)));
  }
  LWLockRelease(passwordpolicy_lock_history);

error:
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}

void passwordpolicy_hash_history_save(void)
{
  char *sql_delete, *sql_insert;
  Datum params_delete[2], params_insert[3];
  HASH_SEQ_STATUS hash_seq;
  int ret, i;
  PasswordPolicyHistory *entry;
  SPIPlanPtr plan_delete, plan_insert;
  TimestampTz oldest_change;

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
    ereport(INFO, (errmsg("passwordpolicy: extension is not installed, skipping password history")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy delete dropped users history");
  ret = SPI_execute("DELETE FROM passwordpolicy.accounts_password_history h "
                    "WHERE NOT EXISTS (SELECT 1 FROM pg_user u WHERE u.usename = h.usename)",
                    false, 0);
  if (ret != SPI_OK_DELETE)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to delete password history removed users")));
    goto error;
  }

  sql_delete = "DELETE FROM passwordpolicy.accounts_password_history "
               "WHERE usename = $1 AND changed_at < $2";

  plan_delete = SPI_prepare(sql_delete, 2, (Oid[]){TEXTOID, TIMESTAMPTZOID});
  if (plan_delete == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history delete")));
    goto error;
  }

  sql_insert = "INSERT INTO passwordpolicy.accounts_password_history "
               "(usename, password_hash, changed_at) "
               " VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";

  plan_insert = SPI_prepare(sql_insert, 3, (Oid[]){TEXTOID, TEXTOID, TIMESTAMPTZOID});
  if (plan_insert == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history insert")));
    goto error;
  }

  LWLockAcquire(passwordpolicy_lock_history, LW_SHARED);
  hash_seq_init(&hash_seq, passwordpolicy_hash_history);
  while ((entry = (PasswordPolicyHistory *)hash_seq_search(&hash_seq)) != NULL)
  {
    oldest_change = 0;
    params_insert[0] = CStringGetTextDatum(entry->key);
    for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
    {
      if (entry->hashes[i].changed_at != 0)
      {
        params_insert[1] = CStringGetTextDatum(entry->hashes[i].password_hash);
        params_insert[2] = TimestampTzGetDatum(entry->hashes[i].changed_at);
        if (oldest_change == 0 || oldest_change > entry->hashes[i].changed_at)
          oldest_change = entry->hashes[i].changed_at;
        pgstat_report_activity(STATE_RUNNING, "passwordpolicy insert history");
        ret = SPI_execute_plan(plan_insert, params_insert, NULL, false, 0);
        if (ret != SPI_OK_INSERT)
        {
          ereport(ERROR, (errmsg("passwordpolicy: failed to executre password history insert")));
          LWLockRelease(passwordpolicy_lock_history);
          goto error;
        }
      }
    }

    if (oldest_change > 0)
    {
      params_delete[0] = CStringGetTextDatum(entry->key);
      params_delete[1] = TimestampTzGetDatum(oldest_change);
      pgstat_report_activity(STATE_RUNNING, "passwordpolicy delete history");
      ret = SPI_execute_plan(plan_delete, params_delete, NULL, false, 0);
      if (ret != SPI_OK_DELETE)
      {
        ereport(ERROR, (errmsg("passwordpolicy: failed to executre password history delete")));
        LWLockRelease(passwordpolicy_lock_history);
        goto error;
      }
    }
  }
  LWLockRelease(passwordpolicy_lock_history);

error:
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}