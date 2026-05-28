# GPG Signing

How to sign KilasOS releases with GPG.

## Generate a release key

```bash
gpg --full-generate-key
# Select: RSA and RSA (default)
# Key size: 4096
# Key validity: 2y
# Real name: KilasOS Release
# Email: releases@kilasos.org
```

## Export the public key

```bash
gpg --export --armor releases@kilasos.org > packaging/apt-repo/kilasos-release.asc
```

## Sign artifacts

```bash
# Detached signature for checksums
gpg --detach-sign --armor bin/SHA256SUMS

# Clearsign the apt Release file
gpg --clearsign --armor \
  --output packaging/apt-repo/dists/stable/Release.asc \
  packaging/apt-repo/dists/stable/Release
```

## Verify signatures (end users)

```bash
# Import the release key
gpg --import packaging/apt-repo/kilasos-release.asc

# Verify checksums
gpg --verify bin/SHA256SUMS.asc bin/SHA256SUMS
sha256sum -c bin/SHA256SUMS

# Verify apt repository
gpg --verify packaging/apt-repo/dists/stable/Release.asc
```
