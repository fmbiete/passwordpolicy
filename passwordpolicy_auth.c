/*-------------------------------------------------------------------------
 *
 * passwordpolicy_auth.c
 *      Authentication checks for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_auth.h"

#include <utils/hsearch.h>
#include <utils/timestamp.h>

#include "passwordpolicy_shmem.h"
#include "passwordpolicy_vars.h"

void passwordpolicy_client_authentication(Port *port, int status)
{
  bool found;
  int failures, microsecs;
  long int secs;
  TimestampTz last_failure;
  PasswordPolicyAccount *entry;

  /*
      Client Authentication hook executes after the authentication is done (ok or error),
      this is a poor man approach as we don't avoid brute force attacks
     */

  if (passwordpolicy_prev_client_authentication_hook)
    passwordpolicy_prev_client_authentication_hook(port, status);

  if (status == STATUS_EOF)
    return;

  if (!passwordpolicy_shmem_check())
    return;

  if (guc_passwordpolicy_lock_after == 0)
    return;

  entry = (PasswordPolicyAccount *)hash_search(passwordpolicy_hash_accounts, port->user_name, HASH_FIND, &found);
  if (!found)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' not found in account table", port->user_name)));
    return;
  }

  if (pg_atomic_read_u64(&(entry->deleted)) == 1)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' marked for deletion, ignoring account", port->user_name)));
    return;
  }

  // Soft-lock
  failures = pg_atomic_read_u64(&(entry->failures));
  // account soft-locked
  if (failures >= guc_passwordpolicy_lock_after)
  {
    // auto soft-unlock enabled
    if (guc_passwordpolicy_lock_auto_unlock)
    {
      // auto soft-unlock delay
      last_failure = pg_atomic_read_u64(&(entry->last_failure));
      TimestampDifference(last_failure, GetCurrentTimestamp(), &secs, &microsecs);
      if (secs < guc_passwordpolicy_lock_auto_unlock_after)
      {
        ereport(DEBUG3, (errmsg("passwordpolicy: maximum number of failed connections exceeded for '%s' and auto unlock time not passed",
                                port->user_name)));
        goto error;
      }
    }
    else
    {
      // auto soft-unlock disabled
      ereport(DEBUG3, (errmsg("passwordpolicy: maximum number of failed connections exceeded for '%s' and auto unlock disabled",
                              port->user_name)));
      goto error;
    }
  }

  if (status == STATUS_OK)
  {
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' failures reset", port->user_name)));
    pg_atomic_write_u64(&(entry->failures), 0);
  }
  else
  {
    failures = pg_atomic_add_fetch_u64(&(entry->failures), 1);
    pg_atomic_write_u64(&(entry->last_failure), GetCurrentTimestamp());
    ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' failures '%d/%d",
                            port->user_name, failures, guc_passwordpolicy_lock_after)));
    if (failures >= guc_passwordpolicy_lock_after)
    {
      goto error;
    }
  }

  goto end;

error:
  /* introduce a delay, poor man method to reduce impact on sequential attacks */
  if (guc_passwordpolicy_lock_failure_delay > 0)
    pg_usleep(guc_passwordpolicy_lock_failure_delay * USECS_PER_SEC);
  /* terminate the backend */
  ereport(FATAL, (errmsg("passwordpolicy: maximum number of failed connections exceeded for '%s'",
                         port->user_name)));

end:
  return;
}