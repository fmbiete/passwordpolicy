/*-------------------------------------------------------------------------
 *
 * passwordpolicy_shmem.h
 *      Functions to manage shared memory
 *
 * Copyright (c) 2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_SHMEM_H_
#define _PASSWORDPOLICY_SHMEM_H_

#include <postgres.h>

/* Hook functions */
extern void passwordpolicy_shmem_startup(void);
extern void passwordpolicy_shmem_shutdown(int code, Datum arg);
extern void passwordpolicy_shmem_request(void);

#endif
