/*-------------------------------------------------------------------------
 *
 * passwordpolicy_bgw.h
 *      Background worker for passwordpolicy
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_BGW_H_
#define _PASSWORDPOLICY_BGW_H_

#include <postgres.h>

extern PGDLLEXPORT void PasswordPolicyBgwMain(Datum arg);

#endif
