ALTER SYSTEM SET password_policy.min_uppercase_letter = 0;

ALTER SYSTEM SET password_policy.min_lowercase_letter = 0;

ALTER SYSTEM SET password_policy.min_special_chars = 0;

ALTER SYSTEM SET password_policy.min_numbers = 0;

ALTER SYSTEM SET password_policy.min_password_len = 6;

SELECT pg_reload_conf();

;