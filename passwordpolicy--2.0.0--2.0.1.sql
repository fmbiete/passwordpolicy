/* passwordpolicy/passwordpolicy--1.1.0--2.0.0.sql */

-- complain if script is sourced in psql
\echo Use "ALTER EXTENSION passwordpolicy UPDATE TO '2.0.1'" to load this file. \quit

-- Include table in pg_dump
SELECT pg_catalog.pg_extension_config_dump('passwordpolicy.accounts_lockable', '');

SELECT pg_catalog.pg_extension_config_dump('passwordpolicy.accounts_password_policy', '');