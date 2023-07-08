# contrib/passwordpolicy/Makefile

EXTENSION = passwordpolicy
MODULE_big = passwordpolicy
OBJS = passwordpolicy.o $(WIN32RES)
PGFILEDESC = "passwordpolicy - user password checks"

DATA = passwordpolicy--1.0.0.sql passwordpolicy--1.0.0--1.1.0.sql

REGRESS_OPTS  = --inputdir=test --outputdir=test --load-extension=passwordpolicy --user=postgres
REGRESS = passwordpolicy_test01 passwordpolicy_test02 passwordpolicy_test03 passwordpolicy_test04

PG_CFLAGS = -DUSE_CRACKLIB '-DCRACKLIB_DICTPATH="/var/cache/cracklib/postgresql_dict"'
SHLIB_LINK = -lcrack

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
