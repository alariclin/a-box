# A-Box final-v8-rc2 changelog

Build: `2026-07-28-final-v8-rc2`
Build epoch: `2026072804`

## Corrections over final-v8

- Made per-file core ownership deletion fully fail-closed before the first unlink.
- Rejects unrecorded directory members, changed files, links, hard-linked files, unsafe ownership, and unsafe modes.
- Validates the ownership manifest as a root-owned 0600 regular file with a size bound.
- Tightened the legacy backup importer: `/etc/ddr` is no longer an unrestricted prefix; only known A-Box state/runtime names are accepted, and stale trust/runtime metadata is discarded.
- Fixed language and backup-menu prompt ranges.
- Removed the unused sibling recovery-key writer; recovery keys are exported only by explicit command to protected storage.
- Retained v7 sibling-key reading only for controlled backward recovery, with fingerprint pinning or explicit strong confirmation.
- Preserved the core-upgrade signal rollback and target cleanup introduced in final-v8.

## Compatibility policy

- New backups remain manifest v3 with SHA-256 and host HMAC authentication.
- Old backups must pass the strict legacy validator and are converted to a new v3 archive before restore.
- Unknown legacy `/etc/ddr` files are rejected instead of being imported as root content.
