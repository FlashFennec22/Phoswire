# Phoswire
A lightweight Windows 11 firewall coded in rust.

Currently usable only via the terminal. Has a learning mode for easy deployment.

This is very early code and a hobby project besides so think twice before running it on your own machine.

## What it does and does not protect against

Phoswire blocks every connection unless the program making it is on the whitelist. It sits alongside Windows Firewall: traffic has to be accepted by both.

Things worth knowing before relying on it:

- **It stops filtering when its service is not running.** The filters are removed when the service stops, so a stopped service can never lock you out of the network. The price is that nothing is filtered early in boot, during an upgrade, or after `phoswire stop`. The service restarts itself after a crash.
- **Rules trust a path, not a file.** Whatever is at a whitelisted path may connect. A rule for a program outside `Program Files` and `Windows`, or in a folder there that ordinary users may write to, can be defeated by replacing that file, which needs no administrator rights. `phoswire list` marks these rules as `unprotected path`.
- **Learning mode trusts everything that connects**, including anything unwanted that is already running. Use it briefly, on a machine you believe is clean: `phoswire mode learning --hours 8` switches back to normal by itself. Learning switched on by the installer ends after 24 hours; from then on anything not yet whitelisted is blocked, and `phoswire blocked` shows what to allow.
- **Local connections are always allowed.** A program that is not whitelisted can still talk to a whitelisted one on the same machine, so a whitelisted local proxy or VPN client lets everything through.
- **Name lookups are always allowed** through the Windows DNS Client, for every program. Data can be smuggled out inside DNS queries.
- **Virtual machines and WSL 2 are probably not covered.** Their traffic does not pass through the part of Windows that Phoswire filters. This has not been tested.

## Files

Configuration and the log live in `%ProgramData%\Phoswire`, which only SYSTEM and Administrators can read or change. If the service finds a file there that was not created by an administrator, it does not use it and renames it to `*.untrusted`. If the folder itself cannot be made safe, the service runs with an empty whitelist, saves nothing, and says so in `phoswire status`.
