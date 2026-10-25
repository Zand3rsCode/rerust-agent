# Changelog

## v0.1.0 - 2026-10-25
- First version: the ReRust panel's agent API v1 in one program - servers (start, stop, logs, files, plugins),
  game installs (DepotDownloader), Oxide / Carbon, backups (make, upload, restore), wipes, machine stats, secure RCON,
  self-update from signed releases.
- Its own certificate, pinned by the panel at pairing (no domain or Let's Encrypt needed).
- `install.sh`: installs, updates, takes over an older ReRust (PHP) install, uninstalls.
