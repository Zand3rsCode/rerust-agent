# ReRust Agent

The game-machine agent for the [ReRust](https://github.com/Zand3rsCode) panel: one small program that runs Rust
(Steam) dedicated servers on a Linux machine for a ReRust panel somewhere else. No PHP, web server, database or
certbot needed on the game machine.

**Status: in development** - not ready for use yet.

## What it does

- Starts, stops and watches `RustDedicated` processes in `/srv/rust/<server>`.
- Installs and updates the game (DepotDownloader) and Oxide / Carbon.
- Files, plugins, console logs, backups, restores and wipes for the panel.
- Machine stats (CPU, memory, disks, network) for the panel's dashboard.
- Secure RCON for the panel: `wss://` to the agent, passed to the server's RCON on `127.0.0.1`. RCON is never
  opened to the network.

Only a paired ReRust panel can use it: every request needs the machine key, and the agent can be limited to the
panel's IP address.

## Install

Ubuntu 26.04, as root (the exact command, with your pairing details, comes from the panel: Settings → Machines):

```sh
curl -fsSL https://github.com/Zand3rsCode/rerust-agent/releases/download/<version>/install.sh | sudo sh -s -- --panel-ip <panel IP>
```

The installer checks the download's checksum and signature before it installs anything, then prints a **pairing
code**. Paste it into the panel (Settings → Machines → Add machine) together with the machine's address.

## Licence

MIT - see [LICENSE](LICENSE).
