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
#ifndef _PASSWORDPOLICY_AUTH_H_
#define _PASSWORDPOLICY_AUTH_H_

#include <postgres.h>
#include <libpq/libpq-be.h>

extern PGDLLEXPORT void passwordpolicy_client_authentication(Port *port, int status);

#endif
