# Apt Repository Layout

The apt repository for KilasOS will be hosted on GitHub Pages once
`git push` is enabled (carryover #9).

## Directory structure

```
packaging/apt-repo/
  dists/stable/
    Release              # apt Release file (clearsigned with GPG)
    Release.gpg          # GPG detached signature
    InRelease            # InRelease (if using inline signing)
    main/
      binary-amd64/
        Packages         # apt package index for amd64
        Packages.gz
      binary-arm64/
        Packages         # apt package index for arm64
        Packages.gz
  pool/main/k/kilasos-nasd/
    kilasos-nasd_<version>_amd64.deb
    kilasos-nasd_<version>_arm64.deb
```

## How to assemble (when publishing is enabled)

1. Build both `.deb` packages: `bash scripts/build-deb.sh`
2. Copy `.deb` files to `pool/main/k/kilasos-nasd/`
3. Generate `Packages` files:
   ```bash
   cd packaging/apt-repo
   dpkg-scanpackages --multiver pool/ > dists/stable/main/binary-amd64/Packages
   gzip -9c dists/stable/main/binary-amd64/Packages > dists/stable/main/binary-amd64/Packages.gz
   # Repeat for arm64
   ```
4. Generate `Release` file:
   ```bash
   apt-ftparchive release dists/stable > dists/stable/Release
   ```
5. Sign with GPG: `gpg --clearsign --armor -o dists/stable/InRelease dists/stable/Release`

## User-facing sources.list entry

```
deb [signed-by=/usr/share/keyrings/kilasos-release.asc] https://<pages-url>/ stable main
```
