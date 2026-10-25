# Changelog

## v0.2.3 - 2026-10-25
- Fix: `install.sh` stopped with "could not download the agent from .../v26.04.1 LTS (Resolute Raccoon)" - Ubuntu's
  `/etc/os-release` sets `VERSION` and overwrote the installer's own. It is read separately now.

## v0.2.2 - 2026-10-25
- Backups include `HarmonyMods_Data` (the Harmony mods' own settings and data) next to `HarmonyMods`. A restore puts it
  back always - it is data, not code (HarmonyMods itself still only when asked for).

## v0.2.1 - 2026-10-25
- The agent's default port is now **8085** (was 443): port 443 is often taken by a website on the same machine. Use
  `https://<machine>:8085` as the machine's address in the panel; `--port` still picks another one (e.g. `--port 443`).
  Running the installer again on a machine keeps the port it has (no `--port` needed).

## v0.2.0 - 2026-10-25
Security fixes from a review before the first install (v0.1.0 was withdrawn the same day, never installed):
- Game servers run as their own systemd service each (`rerust-server@<name>`), as user `rerust`, and see only their
  own folder - no other server, no backups, nothing of the agent. The agent runs as its own user `rerust-agent` and
  may only start, stop and kill those services (a polkit rule).
- The agent's program belongs to root: neither the agent nor a game server can replace it. Updates are installed by
  a separate root step that checks the signature, the version and the checksum itself.
- No capabilities: systemd opens the HTTPS port (`rerust-agent.socket`), so Rust servers inherit nothing.
- Releases sign their version too (no old build under a new tag); DepotDownloader is a pinned version, checked by its
  SHA-256 (3.4.0).
- Secure RCON needs the machine key and reaches only the registered servers' RCON ports.
- Wrong keys never lock out the panel's right key; pairing takes a small body only, codes last 60 minutes, and a
  paired machine needs `pair --replace` for a new panel.
- Every file operation goes through Go's `os.Root` (no way out of a server folder through links, also not while a
  file is swapped); FIFOs and devices are never read; a linked server folder is refused; no delete while running.
- Restoring a backup leaves plugins and HarmonyMods alone unless asked for (they run code).
- RCON passwords masked in log downloads and quoted values; one job per server at a time; uploads never replace a
  backup; release downloads stay on GitHub's own hosts.
- `install.sh`: runs only once fully downloaded, stricter `--port` / `--panel-ip` checks, `--uninstall` removes only
  its own firewall rules, `--replace-php-agent` asks before stopping nginx and takes the web server out of the game's
  group; systemd hardening for every service.

## v0.1.0 - 2026-10-25
- First version: the ReRust panel's agent API v1 in one program - servers (start, stop, logs, files, plugins),
  game installs (DepotDownloader), Oxide / Carbon, backups (make, upload, restore), wipes, machine stats, secure RCON,
  self-update from signed releases.
- Its own certificate, pinned by the panel at pairing (no domain or Let's Encrypt needed).
- `install.sh`: installs, updates, takes over an older ReRust (PHP) install, uninstalls.
