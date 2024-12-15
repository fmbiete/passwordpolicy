# passwordpolicy

The `passwordpolicy` is like the regular `PostgreSQL passwordcheck` module, except that you can dynamically define the complexity requirements. The `passwordpolicy` module checks users' passwords whenever they are set with `CREATE ROLE` or `ALTER ROLE`. If a password is considered too weak, it will be rejected and the command will terminate with an error.
You can also use multiple passwordcheck modules as long as `passwordpolicy` is defined first in `shared_preload_libraries`, all the checks will be executed until the first failure or the final success.

## Installing by compiling source code

**Prerequisites**

`RHEL`:

```bash
# add postgres repo
dnf install https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

# enable EPEL
dnf install epel-release

# install build tools
dnf install openssl-devel gcc make redhat-rpm-config ccache

# (optional) install cracklib
dnf install --enablerepo=crb cracklib cracklib-devel cracklib-dicts words

# (optional) create dictionary
mkdir /var/cache/cracklib
mkdict /usr/share/dict/* | packer /var/cache/cracklib/postgresql_dict

# install postgres
dnf install --enablerepo=crb postgresql15-server postgresql15-libs postgresql15-devel postgresql15-contrib

# (run as postgres) initialize databasse
/usr/pgsql-15/bin/initdb
```

To build it, just do this:

```bash
make
make install
make installcheck
```

If you encounter an error such as:

```
make: pg_config: Command not found
```

Be sure that you have pg_config installed and in your path. If you used
a package management system such as RPM to install PostgreSQL, be sure
that the -devel package is also installed.


## Using the module

To enable this module, add '`passwordpolicy`' to
`shared_preload_libraries` in `postgresql.conf`, then restart the server.

## Configurations

**Settings are dynamic, but the new values will be only visible for new database sessions.**

Configure the `passwordpolicy` module in `postgresql.auto.conf`.

### Password Checks
| GUC | Data Type | Default Value | Explanation |
|---|---|---|---|
| password_policy.enable_dictionary_check | boolean | false | Enable password checks against a dictionary |
| password_policy.min_password_len | number (>0) | 15 | Minimum password length |
| password_policy.min_special_chars | number (>=0) | 1 | Minimum number of non alpha-numeric characters |
| password_policy.min_numbers | number (>=0) | 1 | Minimum number of numeric characters |
| password_policy.min_uppercase_letter | number (>=0) | 1 | Minimum number of upper case letters |
| password_policy.min_lowercase_letter | number (>=0) | 1 | Minimum number of lower case letters |
| password_policy.require_validuntil | boolean | false | Requires a Valid Until when setting a password |

### (optional) - Dictionary check
If you want to use the dictionary check, you first need to create a dictionary
```
mkdir /var/cache/cracklib
mkdict /usr/share/dict/* | packer /var/cache/cracklib/postgresql_dict
```

Then you need to enable this `passwordpolicy` setting in `postgresql.auto.conf`
```
password_policy.enable_dictionary_check = true    # Enable checks against a dictionary
```

### (optional) - Required Valid Until clause
This rule will require a valid until value **only** when setting a new password. Creation of user accounts without password is not affected, or any modification that does not involve a password.

### Account Soft-Lock during login
This feature requires installing the extension in _postgres_ database.
```
CREATE EXTENSION passwordpolicy;
```

| GUC | Data Type | Default Value | Explanation |
|---|---|---|---|
| password_policy_lock.auto_unlock | boolean | true | Automatically soft-unlock an account |
| password_policy_lock.auto_unlock_after | number (>=0) | 0 | Automatically soft-unlock an account after this number of seconds since the last failed login attempt |
| password_policy_lock.failure_delay | number (>=0) | 5 | Delay in seconds applied to rejected login attempts |
| password_policy_lock.include_all | boolean | true | Consider all user accounts in the database for soft-lock |
| password_policy_lock.max_number_accounts | number (>0) | 100 | Number of user accounts in the system, used to reserve memory (approximate to avoid out of memory during operations) |
| password_policy_lock.number_failures | number (>0) | 5 | Number of failed attempts before soft-locking an account |

PostgreSQL does not support blocking authentication attempts, the authentication process will happen and before returning the result to the client it will be intercepted to simulate a soft-locking.

**This will not reduce the impact of an authentication DoS attack.**

For each user we keep the number of consecutive login failures and the time of the last failure.

When the number of consecutive failed logins reaches ```password_policy_lock.number_failures``` the extension applies a delay ```password_policy_lock.failure_delay``` and returns an error message.

If ```password_policy_lock.auto_unlock``` is enabled, the account will automatically unlock after ```password_policy_lock.auto_unlock_after``` seconds. Use 0 to automatically soft-unlock the account on the next attempt.

If ```password_policy_lock.auto_unlock = false```, any account soft-locked will remain that way until a super user executes the manual unlock function:
```
SELECT passwordpolicy.account_locked_reset('username');
```


#### List of accounts to soft-lock
By default a list of all the existing users in the system ```pg_user``` is read.

If ```password_policy_lock.include_all = false``` only the list of user names present in ```postgres``` ```passwordpolicy.accounts_lockable``` table is considered for soft-lock. This table is created by the extension on installation and a superuser can manually insert user names.

This list of users monitored for soft-lock is maintained by the background worker. You can force an update reloading the system configuration.

The list of users monitored can be viewed calling this function:
```
SELECT passwordpolicy.accounts_locked() ORDER BY usename;
```
Notice that this function requires a shared lock, it will not impact the login process of new sessions, but it will impact the background worker of this extension.


#### Performance
It's recommended to indicate the approximate number of users in the database with ```password_policy_lock.max_number_accounts```. Failure to do so could lead to poor login performance, out of memory errors and/or accounts not being considered.

No lock is required during login, there should not be any impact for concurrent logins, even from the same user.


### Password History
This feature requires installing the extension in _postgres_ database.
```
CREATE EXTENSION passwordpolicy;
```

| GUC  | Data Type | Default Value  | Explanation |
|---|---|---|---|
| password_policy_history.max_number_accounts | number (>0) | 100 | Number of user accounts in the system, used to reserve memory (approximate to avoid out of memory during operations) |
| password_policy_history.max_password_history | number (>0) | 5 | Number of password history versions to keep (0 to disable this feature) |

This feature will save the password hash of the last ```password_policy_history.max_password_history``` password changes per user in ```postgres``` database ```passwordpolicy.accounts_password_history``` table.

The content of this table is read during the database start and flushed to table every minute. It could contain stale data and should only be used as a reference.

When the number of password changes per user exceeds ```password_policy_history.max_password_history``` the oldest version is deleted.


## Testing

Using vagrant:

```bash
vagrant up
vagrant provision --provision-with install
```

## More information

For more details, please read the manual of the original module:

[https://www.postgresql.org/docs/current/static/passwordcheck.html](https://www.postgresql.org/docs/current/static/passwordcheck.html)
