/*-------------------------------------------------------------------------
 *
 * passwordpolicy_auth.h
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

#include "passwordpolicy_vars.h"

void passwordpolicy_client_authentication(Port *port, int status)
{
  bool found;
  int failures;
  PasswordPolicyAccount *entry;

  if (prev_client_authentication_hook)
    prev_client_authentication_hook(port, status);

  /* Safety checks */
  if (!passwordpolicy_shm || !passwordpolicy_hash_accounts ||
      !pg_atomic_unlocked_test_flag(&(passwordpolicy_shm->flag_shutdown)))
    return;

  /*
    Client Authentication hook executes after the authentication is done (ok or error),
    this is a poor man approach as we don't avoid brute force attacks
   */
  if (status != STATUS_EOF && guc_passwordpolicy_lock_after > 0)
  {
    entry = (PasswordPolicyAccount *)hash_search(passwordpolicy_hash_accounts, port->user_name, HASH_FIND, &found);
    if (found)
    {
      if (status == STATUS_OK)
      {
        ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' failures reset", port->user_name)));
        pg_atomic_write_u64(&(entry->failures), 0);
      }
      else
      {
        failures = pg_atomic_add_fetch_u64(&(entry->failures), 1);
        ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' failures '%d/%d",
                                port->user_name, failures, guc_passwordpolicy_lock_after)));
        pg_atomic_write_u64(&(entry->last_failure), (int)time(NULL));
        if (failures >= guc_passwordpolicy_lock_after)
        {
          /* introduce a delay, poor man method to reduce impact on sequential attacks */
          pg_usleep(guc_passwordpolicy_login_failure_delay * USECS_PER_SEC);
          /* terminate the backend */
          ereport(FATAL, (errmsg("passwordpolicy: maximum number of failed connections exceeded for '%s' (%d/%d)",
                                 port->user_name, failures, guc_passwordpolicy_lock_after)));
        }
      }
    }
    else
    {
      ereport(DEBUG3, (errmsg("passwordpolicy: account '%s' not found in account table", port->user_name)));
    }
  }
}