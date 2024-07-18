# Securing rsync

We need to `rsync` files from a `remote` server to a `local` server
through a jumphost.  To do this with minimal risk, we:

1. Create an ed25519 key without a passphrase, the private key is stored
   in `local`.
2. Only allow `no-pty` logins on the jumphost using the key.
3. Limit logins using the key to running `rsync` on `remote`.

Restrictions 2 and 3 are enforced by parameterizing the authorization in
`.ssh/authorized_keys`.  In the jumphost we use:

```{authorized_keys}
no-pty,no-user-rc,command="<path>/ssh-log.sh rsync" ssh-ed25519 <key> <user>@<host>
```

In the `remote` we use:

```{authorized_keys}
command="<path>/ssh-verify-rsync.sh" ssh-ed25519 <key> <user>@<host>
```

On the `remote`, `ssh-verify-rsync.sh` must have `r-x` permisions for
the user logging in: Remove write permisions to prevent `rsync` from
overwriting the file.

On `local`, the `.ssh/config` file should specify the ed25519 key on
both the `remote` and on the jumphost's `ProxyCommand`:

```{ssh_config}
Host remote-rsync
    User username
    IdentityFile ~/.ssh/id_ed25519_rsync
    HostName remote.domain
    ProxyCommand ssh -i ~/.ssh/id_ed25519_rsync jumphost.domain -W %h:%p
```

In the `crontab`, remember to set the `MAILTO` variable to an e-mail
gets attention.  On a vanilla Debian server, you may need to run
`dpkg-reconfigure exim4-config` and set the host as "Internet site" or
it will not attempt to send e-mails to remote domains.

Check that `rsync-shodan.sh` is `chmod`ed `+x`.
