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

### Password Complexity
```
password_policy.min_password_len = 15      # Set minimum password length
password_policy.min_special_chars = 1      # Set minimum number of special chracters
password_policy.min_numbers = 1            # Set minimum number of numeric characters
password_policy.min_uppercase_letter = 1   # Set minimum number of upper case letters
password_policy.min_lowercase_letter = 1   # Set minimum number of lower casae letters
```

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

### Setting a password requires a Valid Until clause
```
password_policy.require_validuntil = true
```

This rule will require a valid until value **only** when setting a new password. Creation of user accounts without password is not affected, or any modification that does not involve a password.

### Delaying failed logins
```
password_policy_lock.failure_delay = 5              # Number of seconds to delay logins after number of failures
password_policy_lock.max_number_accounts = 100      # Number of user accounts, it can be smaller than the number of accounts in the system
password_policy_lock.number_failures = 5            # Number of login failures before rejecting further logins
password_policy_lock.include_all = true             # Consider all the accounts in the system
password_policy_lock.auto_unlock = true             # Login with failed accounts will automatically work...
password_policy_lock.auto_unlock_after = 0          # ...after N seconds (0: next login attempt)
```

Install the extension in _postgres_ database.
```
CREATE EXTENSION passwordpolicy;
```

#### List of lock accounts
By default a list of all the existing users in the system (pg_user) is read.

If ```password_policy_lock.include_all = false``` then a list of user names is read from ```passwordpolicy.accounts_lockable``` in ```postgres``` database. This table is created by the extension on installation.

It's recommended to indicate the approximate number of users in the database with ```password_policy_lock.max_number_accounts```. Failure to do so could lead to poor login performance and accounts not being considered.

This list of users is maintained by the background worker. You can force an update reloading system configuration dynamically.

The list of users monitored can be viewed calling this function:
```
SELECT passwordpolicy.accounts_locked() ORDER BY usename;
```
Notice that this function requires a shared lock, it will not impact the login process of new sessions, but it will impact the background worker of this extension.

#### Account soft-locking
**PostgreSQL does not support blocking the authentication process, this will always happen, so there will be impact in the database server. This extension only modifies the message returned to the user to emulate a user locking.**

For each user we keep the number of consecutive login failures and the time of the last failure.

When the number of consecutive failed logins reaches ```password_policy_lock.number_failures``` the extension applies a delay ```password_policy_lock.failure_delay``` and returns an error message.

If ```password_policy_lock.auto_unlock``` is enabled, the account will automatically unlock after ```password_policy_lock.auto_unlock_after``` seconds. Use 0 to automatically soft-unlock the account on the next attempt.

If ```password_policy_lock.auto_unlock = false```, any account soft-locked will remain that way until a super user executes the manual unlock function:
```
SELECT passwordpolicy.account_locked_reset('username');
```



When a login is successful the number of failed accounts is reset.


## Testing

Using vagrant:

```bash
vagrant up
vagrant provision --provision-with install
```

## More information

For more details, please read the manual of the original module:

[https://www.postgresql.org/docs/current/static/passwordcheck.html](https://www.postgresql.org/docs/current/static/passwordcheck.html)
