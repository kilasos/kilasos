# Files

> **Status:** outline.

The Files tab is a browser-based file manager. It is intentionally narrow:
no editing, no preview-by-default, no embedded terminal. Use it for upload,
download, basic organization, ACL inspection, and trash recovery.

## Chapter map

1. Browsing — the pool / dataset selector
2. Upload (single, multipart, drag-and-drop)
3. Search and tree view
4. Preview (text + image + archive contents)
5. Folder-zip download
6. Trash and restore
7. ACL inspection and editing
8. Path-traversal protections (what `safePath()` does)

## Browsing

`[TODO]` how the pool list is built from `zfs list`, dataset selector,
breadcrumb, listing with `ls -lh`-like columns.

## Upload

`[TODO]` single-file POST, multipart upload for big files, chunk size,
progress indicator, where partial uploads land.

## Search and tree

`[TODO]` `find`-backed search semantics, tree view performance limits.

## Preview

`[TODO]` text preview size cap, syntax highlighting (none), images,
listing inside zips / tarballs without extracting.

## Folder-zip download

`[TODO]` `/files/zip` endpoint, streaming response, no temp files.

## Trash and restore

`[TODO]` per-pool trash directory, retention, restore semantics, empty.

## ACLs

`[TODO]` POSIX ACL display, `setfacl` invocation, inheritance rules.

## safePath() protections

`[TODO]` the file manager's path-traversal guards — `..` blocked, symlink
following gated, exclusive-to-`/mnt`. See the regression tests in
`internal/api/safe_path_test.go`.

---

**Previous:** [Shares ←](shares.md)
**Next:** [Network →](network.md)
