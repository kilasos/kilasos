# Shares

> **Status:** outline.

KilasOS exports filesystems over SMB (Samba) and NFS, plus a built-in HTTP
"share-link" endpoint for guest-friendly downloads.

## Chapter map

1. SMB shares — local users
2. SMB shares — AD-joined hosts
3. NFS exports — `/etc/exports.d/kilasos.exports` model
4. ACLs and POSIX permissions
5. Share-link endpoint (public download URLs with optional expiry)
6. Active SMB connections + session enumeration
7. Quota and per-share accounting
8. Troubleshooting (Wireshark of last resort)

## SMB — local users

`[TODO]` create-share wizard → user picker → permissions → smb.conf
fragment → reload smbd.

## SMB — AD-joined hosts

`[TODO]` join domain (`net ads join`), Kerberos ticket lifetime, mapping
AD users to Linux UIDs (winbind), idmap config.

## NFS exports

`[TODO]` create-export wizard → host / subnet / no_root_squash / async,
which file the export ends up in, why `exportfs -ra` rather than reload.

## ACLs and POSIX permissions

`[TODO]` the difference between SMB ACLs and POSIX, when to enable NFSv4
ACL semantics on ZFS datasets, the WebUI's permission editor.

## Share-link endpoint

`[TODO]` the public `/share/{token}` route, generating tokens with expiry,
revocation, security caveats (anyone with the link can download).

## Active connections + sessions

`[TODO]` reading `smbstatus` output, killing a stuck session.

## Quota and accounting

`[TODO]` ZFS dataset quotas vs SMB / NFS quota plumbing, per-user reporting.

## Troubleshooting

`[TODO]` common failure modes: "permission denied" from a domain user,
"file in use" lock errors, stale NFS handle, smb.conf `[global]` overrides.

---

**Previous:** [Storage ←](storage.md)
**Next:** [Files →](files.md)
