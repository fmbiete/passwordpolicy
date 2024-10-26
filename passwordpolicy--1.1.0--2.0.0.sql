/* passwordpolicy/passwordpolicy--1.0.sql */

-- complain if script is sourced in psql
\echo This file is part of a PostgreSQL module, add "passwordpolicy" to "shared_preload_libraries" in "postgresql.conf" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS passwordpolicy;

CREATE TABLE IF NOT EXISTS passwordpolicy.lockable_accounts ( 
  usename VARCHAR(64), 
  CONSTRAINT pk_lockable_accounts PRIMARY KEY(usename) 
);