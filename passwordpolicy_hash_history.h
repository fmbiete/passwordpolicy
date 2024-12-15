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
#ifndef _PASSWORDPOLICY_HASH_HISTORY_H_
#define _PASSWORDPOLICY_HASH_HISTORY_H_

#include <postgres.h>
#include <utils/timestamp.h>

extern PGDLLEXPORT void passwordpolicy_hash_history_add(const char *username, const char *password_hash, TimestampTz changed_at);
extern PGDLLEXPORT bool passwordpolicy_hash_history_exists(const char *username, const char *password_hash);
extern PGDLLEXPORT void passwordpolicy_hash_history_init(void);
extern PGDLLEXPORT void passwordpolicy_hash_history_load(void);
extern PGDLLEXPORT void passwordpolicy_hash_history_save(void);

#endif
