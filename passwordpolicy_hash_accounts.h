/*-------------------------------------------------------------------------
 *
 * passwordpolicy_hash_accounts.h
 *      Hash table for Authentication Accounts
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_HASH_ACCOUNTS_H_
#define _PASSWORDPOLICY_HASH_ACCOUNTS_H_

#include <postgres.h>

extern PGDLLEXPORT void passwordpolicy_hash_accounts_init(void);
extern PGDLLEXPORT void passwordpolicy_hash_accounts_load(void);

#endif
