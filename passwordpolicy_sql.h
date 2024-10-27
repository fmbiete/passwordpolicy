/*-------------------------------------------------------------------------
 *
 * passwordpolicy_sql.h
 *      SQL exported functions for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_SQL_H_
#define _PASSWORDPOLICY_SQL_H_

#include <postgres.h>
#include <fmgr.h>

extern Datum account_locked_reset(PG_FUNCTION_ARGS);
extern Datum accounts_locked(PG_FUNCTION_ARGS);

#endif // _PASSWORDPOLICY_SQL_H_