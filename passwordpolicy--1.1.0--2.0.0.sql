/* passwordpolicy/passwordpolicy--1.1.0--2.0.0.sql */

-- complain if script is sourced in psql
\echo Use "ALTER EXTENSION passwordpolicy UPDATE TO '2.0.0'" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS passwordpolicy;


--
CREATE TABLE IF NOT EXISTS passwordpolicy.accounts_lockable ( 
  usename VARCHAR(64), 
  CONSTRAINT pk_accounts_lockable PRIMARY KEY(usename) 
);


--
DROP FUNCTION IF EXISTS passwordpolicy.accounts_locked();

CREATE FUNCTION passwordpolicy.accounts_locked (
  OUT usename name,
  OUT failure_count integer,
  OUT last_failure timestamp with time zone
)
RETURNS SETOF record
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE;

REVOKE ALL ON FUNCTION passwordpolicy.accounts_locked() FROM PUBLIC;


--
DROP FUNCTION IF EXISTS passwordpolicy.account_locked_reset(name);

CREATE FUNCTION passwordpolicy.account_locked_reset (
  IN usename name
)
RETURNS integer
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE;

REVOKE ALL ON FUNCTION passwordpolicy.account_locked_reset(name) FROM PUBLIC;


--
CREATE TABLE IF NOT EXISTS passwordpolicy.accounts_password_history (
  usename VARCHAR(64),
  password_hash VARCHAR(64),
  changed_at timestamp with time zone,
  CONSTRAINT pk_accounts_password_history PRIMARY KEY(usename, password_hash)
);