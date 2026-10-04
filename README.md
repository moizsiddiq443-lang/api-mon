# api-mon

Personal scheduled checker for a set of API endpoints I maintain. Runs every 30
minutes and on a few fixed daily slots; results land as AES-256-GCM-encrypted
snapshots in `snapshots/` (key is not stored in this repo).

- `run.mjs` — runner; every target, token and window lives inside the encrypted blob
- `config.enc` — encrypted configuration (git history of snapshots is also encrypted)
- `lib/crypt.mjs` — envelope helpers

Nothing readable is committed here by design.