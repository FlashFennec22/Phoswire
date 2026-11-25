# Phoswire
A lightweight Windows 11 firewall coded in rust.

Currently usable only via the terminal. Has a learning mode for easy deployment.

## What is Phoswire for?

Most successful malware these days will expressly target the standard Windows security suite in some fashion or another. Phoswire is intended as a failsafe in the event that those systems are somehow compromised, ideally buying time for an attack to be recognized and mitigated. It also provides a relatively simple way for users to exert control over which applications can or cannot access the internet.

## Is there an installer?

Check the releases page: https://github.com/FlashFennec22/Phoswire/releases

## What does the learning mode do?

Learning Mode is intended to be engaged once and never again; preferably on a clean system during setup. It automatically whitelists outbound traffic for any application attempting to access the internet while it's on. Once it's turned off, a user should manually whitelist any new applications they want to add. **For this reason, Phoswire works best for relatively static deployments. Users who add new software frequently may find it inconvenient.**

## Is it very heavy on system resources?

Phoswire barely exists from a system resources perspective, taking up just over 2 MB of RAM on a typical system.

## Is this a graphical application?

Some aspects of the application are still controlled from the command line at this time.

To change the whitelist without a terminal, right-click the tray icon and choose *Manage whitelist…*. Windows asks for administrator rights (UAC) and then opens a window listing every entry:

- *Add entry…* opens the usual Windows file dialog, limited to programs (`.exe`). Several can be picked at once. A program in a folder that ordinary users can write to gets a warning first (see *Rules trust a path, not a file* below).
- *Delete entry* (or the Delete key) removes the selected entries after asking.

## How do I use it?

Type **phoswire** into an elevated terminal after installing for a list of commands. If you don't know what this means, I would advise against using it for now. The tray icon does expose some functionality graphically.

## Is there an updater function?

No updater is planned.

## What it does and does not protect against

Phoswire blocks every connection unless the program making it is on the whitelist. It sits alongside Windows Firewall: traffic has to be accepted by both.

Things worth knowing before relying on it:

- **It stops filtering when its service is not running.** The filters are removed when the service stops, so a stopped service can never lock you out of the network. The price is that nothing is filtered early in boot, during an upgrade, or after `phoswire stop`. The service restarts itself after a crash.
- **Rules trust a path, not a file.** Whatever is at a whitelisted path may connect. A rule for a program outside `Program Files`, `Windows` and `ProgramData`, or in a folder there that ordinary users may write to, can be defeated by replacing that file, which needs no administrator rights. `phoswire list` marks these rules as `unprotected path`.
- **Rules follow programs that install each update into a new folder.** Windows Defender (`...\Platform\4.18.26080.4-0\MsMpEng.exe`), WebView2, Store apps and many updaters do this, which used to leave the old rule pointing at a folder no longer in use. A rule for such a program now has the version replaced by `*` (`...\Platform\*\MsMpEng.exe`) and allows every version found there. This only happens where only administrators can add folders; elsewhere the rule stays tied to the one version. `phoswire allow --exact` keeps a rule to the version given. Existing rules are converted when the service starts.
- **Updated programs are picked up within a minute.** Rules are checked against the disk every 60 seconds, and within about 10 seconds when a whitelisted program is blocked. A rule whose file is briefly missing during an update keeps its filter rather than being dropped.
- **Learning mode trusts all outbound connections and permanently whitelists programs making them**, including anything unwanted that is already running. Use it briefly, on a machine you believe is clean: `phoswire mode learning --hours 8` switches back to normal by itself. Learning switched on by the installer ends after 24 hours; from then on anything not yet whitelisted is blocked, and `phoswire blocked` shows what to allow.
- **Local connections are always allowed.** A program that is not whitelisted can still talk to a whitelisted one on the same machine, so a whitelisted local proxy or VPN client lets everything through.
- **Name lookups are always allowed** through the Windows DNS Client, for every program. Data can be smuggled out inside DNS queries.
- **Anyone signed in at the computer can read the whitelist and the connections of whitelisted apps** through the tray's read-only pipe. That includes other users of the same machine. They cannot change anything through it.
- **Virtual machines and WSL 2 are probably not covered.** Their traffic does not pass through the part of Windows that Phoswire filters. This has not been tested.

## Files

Configuration and the log live in `%ProgramData%\Phoswire`, which only SYSTEM and Administrators can read or change. If the service finds a file there that was not created by an administrator, it does not use it and renames it to `*.untrusted`. If the folder itself cannot be made safe, the service runs with an empty whitelist, saves nothing, and says so in `phoswire status`.
