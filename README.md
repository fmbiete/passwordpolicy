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

Configure the `passwordpolicy` plugin in `postgresql.auto.conf`.

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

## Testing

Using vagrant:

```bash
vagrant up
vagrant provision --provision-with install
```

## More information

For more details, please read the manual of the original module:

[https://www.postgresql.org/docs/current/static/passwordcheck.html](https://www.postgresql.org/docs/current/static/passwordcheck.html)
