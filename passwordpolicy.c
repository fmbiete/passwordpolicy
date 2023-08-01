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

#include <ctype.h>
#include "postgres.h"
#include "catalog/namespace.h"
#include "utils/guc.h"
#include "commands/user.h"
#include "libpq/crypt.h"
#include "fmgr.h"

#ifdef USE_CRACKLIB
#include <crack.h>
#endif

PG_MODULE_MAGIC;

#include "passwordpolicy.h"

// hook for other passwordcheck modules
static check_password_hook_type prev_check_password_hook = NULL;

// password_policy.min_password_len
int passMinLength = 15;

// password_policy.min_special_chars
int passMinSpcChar = 1;

// password_policy.min_numbers
int passMinNumChar = 1;

// password_policy.min_uppercase_letter
int passMinUpperChar = 1;

// password_policy.min_lowercase_letter
int passMinLowerChar = 1;

// password_policy.enable_dictionary_check
bool passEnableDictionaryCheck = true;

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

static void check_policy(const char *password) {
  int i, pwdlen, letter_count, number_count, spc_char_count, upper_count, lower_count;

  pwdlen = strlen(password);

  letter_count = 0;
  number_count = 0;
  spc_char_count = 0;
  upper_count = 0;
  lower_count = 0;

  for (i = 0; i < pwdlen; i++) {
    /*
     * isalpha() does not work for multibyte encodings but let's
     * consider non-ASCII characters non-letters
     */
    if (isalpha((unsigned char)password[i])) {
      letter_count++;
      if (isupper((unsigned char)password[i])) {
        upper_count++;
      } else if (islower((unsigned char)password[i])) {
        lower_count++;
      }
    } else if (isdigit((unsigned char)password[i])) {
      number_count++;
    } else {
      spc_char_count++;
    }
  }
  if (number_count < passMinNumChar) {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d numeric characters.",
                    passMinNumChar)));
  } else if (spc_char_count < passMinSpcChar) {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d special characters.",
                    passMinSpcChar)));
  } else if (upper_count < passMinUpperChar) {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d upper case letters.",
                    passMinUpperChar)));
  } else if (lower_count < passMinLowerChar) {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("password must contain at least %d lower case letters.",
                    passMinLowerChar)));
  }
}


static void check_password(const char *username, const char *shadow_pass,
                           PasswordType password_type, Datum validuntil_time,
                           bool validuntil_null) {
  /* Call others passwordcheck modules */
  if (prev_check_password_hook) {
    prev_check_password_hook(username, shadow_pass, password_type, validuntil_time, validuntil_null);
    /* if checks in the previous module pass, we proceed with ours */
  }

  if (password_type != PASSWORD_TYPE_PLAINTEXT) {
    /*
     * Unfortunately we cannot perform exhaustive checks on encrypted
     * passwords - we are restricted to guessing. (Alternatively, we could
     * insist on the password being presented non-encrypted, but that has
     * its own security disadvantages.)
     *
     * We only check for username = password.
     */
    char *logdetail = NULL;

    if (plain_crypt_verify(username, shadow_pass, username, &logdetail) == STATUS_OK) {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password cannot contain user name")));
    }
  } else {
    /*
     * For unencrypted passwords we can perform better checks
     */
    const char *password = shadow_pass;
    int pwdlen = strlen(password);
#ifdef USE_CRACKLIB
      const char *reason;
#endif

    /* enforce minimum length */
    if (pwdlen < passMinLength) {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password is too short.")));
    }

    /* check if the password contains the username */
    if (strstr(password, username)) {
      ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                      errmsg("password cannot contain user name.")));
    }

    check_policy(password);

#ifdef USE_CRACKLIB
    if (passEnableDictionaryCheck) {
      /* call cracklib to check password */
      if ((reason = FascistCheck(password, CRACKLIB_DICTPATH))) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("password is easily cracked."),
                        errdetail_log("cracklib diagnostic: %s", reason)));
      }
    }
#endif
  }

  /* all checks passed, password is ok */
}


/*
 * Module initialization function
 */
void _PG_init(void) {
  /* Define password_policy.min_pass_len */
  DefineCustomIntVariable(
      "password_policy.min_password_len",
      "Minimum password length.", NULL, &passMinLength, 15, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Define password_policy.min_special_chars */
  DefineCustomIntVariable(
      "password_policy.min_special_chars",
      "Minimum number of special characters.", NULL, &passMinSpcChar, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Define password_policy.min_numbers */
  DefineCustomIntVariable(
      "password_policy.min_numbers",
      "Minimum number of numeric characters.", NULL, &passMinNumChar, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Define password_policy.min_uppercase_letter */
  DefineCustomIntVariable(
      "password_policy.min_uppercase_letter",
      "Minimum number of upper case letters.", NULL, &passMinUpperChar, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  /* Define password_policy.min_lowercase_letter */
  DefineCustomIntVariable(
      "password_policy.min_lowercase_letter",
      "Minimum number of lower case letters.", NULL, &passMinLowerChar, 1, 0, INT_MAX,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "password_policy.enable_dictionary_check",
      "Enable check against dictionary", NULL, &passEnableDictionaryCheck, false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);


  /* activate password checks when the module is loaded, but allow to use multiple passwordcheck modules */
  prev_check_password_hook = check_password_hook;
  check_password_hook = check_password;
}

void _PG_fini(void) {
  if (prev_check_password_hook) {
    check_password_hook = prev_check_password_hook;
  }
}
