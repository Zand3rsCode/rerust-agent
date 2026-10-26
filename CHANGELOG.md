# Changelog

## v0.2.7 - 2026-10-26
- Fix: `--replace-php-agent` said "took over N folder(s)" but changed nothing when run from `/root` (the usual place):
  the step runs as the game's user, which can't enter `/root`, so it stopped at once - and its error was hidden. The
  server then couldn't be started by the new agent. It now runs from `/`, checks the result and warns about any folder
  it could not open to the agent.
- With `--replace-php-agent` the last step says to **Edit** the machine's existing entry in the panel (its servers stay
  with it), not "Add machine".

## v0.2.6 - 2026-10-26
- Package updates no longer restart the Rust servers. Ubuntu's automatic updates (`needrestart`) restarted every
  service using an updated library - when zlib was updated, a live Rust server was stopped and started again without
  warnings or a save. `install.sh` now writes `/etc/needrestart/conf.d/50-rerust-agent.conf` so the game servers and
  the agent are never restarted that way; they pick up new libraries at their next normal restart. `--uninstall`
  removes the file. Machines already installed get it by running the installer again (or by adding the file by hand).

## v0.2.5 - 2026-10-25
- `install.sh` shows the **public** address for the panel when the machine is behind a router (it showed the
  machine's own private address), and which ports to forward on the router. The public address comes from
  api.ipify.org (or icanhazip.com), asked only when the machine's own address is a private one.

## v0.2.4 - 2026-10-25
- Fix: `install.sh` v0.2.3 stopped with "this copy of install.sh has no version" - building the release had also
  changed its own version check. The check now looks at the version's form, and the release build changes only the
  `VERSION=` line (and tests the result).

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
