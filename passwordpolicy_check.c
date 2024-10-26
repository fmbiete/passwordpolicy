/*-------------------------------------------------------------------------
 *
 * passwordpolicy.c
 *
 * Copyright (c) 2023, Francisco Miguel Biete Banon
 * Copyright (c) 2018-2023, indrajit
 * Copyright (c) 2009-2017, PostgreSQL Global Development Group
 * Author: Laurenz Albe <laurenz.albe@wien.gv.at>
 *
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_check.h"

#include <ctype.h>
#include <catalog/namespace.h>
#include <utils/guc.h>
#include <commands/user.h>
#include <fmgr.h>

#ifdef USE_CRACKLIB
#include <crack.h>
#endif

#include "passwordpolicy_vars.h"

/* forward declaration private functions */
void passwordpolicy_check_password_policy(const char *password);

/*
 * check_password
 *
 * performs checks on an encrypted or unencrypted password
 * ereport's if not acceptable
 *
 * username: name of role being created or changed
 * password: new password (possibly already encrypted)
 * password_type: PASSWORD_TYPE_PLAINTEXT or PASSWORD_TYPE_MD5 (there
 *			could be other encryption schemes in future)
 * validuntil_time: password expiration time, as a timestamptz Datum
 * validuntil_null: true if password expiration time is NULL
 *
 * This sample implementation doesn't pay any attention to the password
 * expiration time, but you might wish to insist that it be non-null and
 * not too far in the future.
 */

void passwordpolicy_check_password(const char *username, const char *shadow_pass,
                                   PasswordType password_type, Datum validuntil_time,
                                   bool validuntil_null)
{
  if (prev_check_password_hook)
    prev_check_password_hook(username, shadow_pass, password_type, validuntil_time, validuntil_null);

  if (validuntil_null && guc_passwordpolicy_require_validuntil)
  {
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                    errmsg("valid until cannot be null")));
  }

  if (password_type != PASSWORD_TYPE_PLAINTEXT)
  {
#if (PG_VERSION_NUM >= 150000)
    const char *logdetail = NULL;
#else
    char *logdetail = NULL;
#endif

    /*
     * Unfortunately we cannot perform exhaustive checks on encrypted
     * passwords - we are restricted to guessing. (Alternatively, we could
     * insist on the password being presented non-encrypted, but that has
     * its own security disadvantages.)
     *
     * We only check for username = password.
     */
    if (plain_crypt_verify(username, shadow_pass, username, &logdetail) == STATUS_OK)
    {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password cannot contain user name")));
    }
  }
  else
  {
    /*
     * For unencrypted passwords we can perform better checks
     */
    const char *password = shadow_pass;
    int pwdlen = strlen(password);
#ifdef USE_CRACKLIB
    const char *reason;
#endif

    /* enforce minimum length */
    if (pwdlen < guc_passwordpolicy_min_length)
    {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password is too short.")));
    }

    /* check if the password contains the username */
    if (strstr(password, username))
    {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password cannot contain user name.")));
    }

    passwordpolicy_check_password_policy(password);

#ifdef USE_CRACKLIB
    if (guc_passwordpolicy_enable_dict_check)
    {
      /* call cracklib to check password */
      if ((reason = FascistCheck(password, CRACKLIB_DICTPATH)))
      {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("password is easily cracked."),
                        errdetail_log("cracklib diagnostic: %s", reason)));
      }
    }
#endif
  }

  /* all checks passed, password is ok */
}

void passwordpolicy_check_password_policy(const char *password)
{
  int i, pwdlen, letter_count, number_count, spc_char_count, upper_count, lower_count;

  pwdlen = strlen(password);

  letter_count = 0;
  number_count = 0;
  spc_char_count = 0;
  upper_count = 0;
  lower_count = 0;

  for (i = 0; i < pwdlen; i++)
  {
    /*
     * isalpha() does not work for multibyte encodings but let's
     * consider non-ASCII characters non-letters
     */
    if (isalpha((unsigned char)password[i]))
    {
      letter_count++;
      if (isupper((unsigned char)password[i]))
      {
        upper_count++;
      }
      else if (islower((unsigned char)password[i]))
      {
        lower_count++;
      }
    }
    else if (isdigit((unsigned char)password[i]))
    {
      number_count++;
    }
    else
    {
      spc_char_count++;
    }
  }

  if (number_count < guc_passwordpolicy_min_number_char)
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d numeric characters.",
                    guc_passwordpolicy_min_number_char)));
  }

  if (spc_char_count < guc_passwordpolicy_min_spc_char)
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d special characters.",
                    guc_passwordpolicy_min_spc_char)));
  }

  if (upper_count < guc_passwordpolicy_min_upper_char)
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d upper case letters.",
                    guc_passwordpolicy_min_upper_char)));
  }

  if (lower_count < guc_passwordpolicy_min_lower_char)
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d lower case letters.",
                    guc_passwordpolicy_min_lower_char)));
  }
}
