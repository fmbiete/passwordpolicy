/*-------------------------------------------------------------------------
 *
 * passwordpolicy_check.h
 *      Password checks for passwordpolicy
 *
 * Copyright (c) 2023-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_CHECK_H_
#define _PASSWORDPOLICY_CHECK_H_

#include <postgres.h>
#include <libpq/crypt.h>

extern PGDLLEXPORT void passwordpolicy_check_password(const char *username, const char *shadow_pass,
                                                      PasswordType password_type, Datum validuntil_time,
                                                      bool validuntil_null);

#endif
