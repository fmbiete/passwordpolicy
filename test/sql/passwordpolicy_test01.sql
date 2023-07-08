LOAD 'passwordpolicy';

ALTER SYSTEM SET password_policy.min_uppercase_letter = 1;

ALTER SYSTEM SET password_policy.min_lowercase_letter = 1;

ALTER SYSTEM SET password_policy.min_special_chars = 1;

ALTER SYSTEM SET password_policy.min_numbers = 1;

ALTER SYSTEM SET password_policy.min_password_len = 15;

SELECT pg_reload_conf();

;
