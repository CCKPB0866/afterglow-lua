# afterglow.lua

PS4 `/dev/apm` clone UaF kernel exploit (afterglow), running inside a **Lua game process**.

Port of [well0nez/afterglow-web](https://github.com/well0nez/afterglow-web) (AGPL-3.0).
Verified on a **retail 14.02** console: full kernel jailbreak, `uid 0`, and GoldHEN up and running.

This is the **game-process Lua host** implementation.

## What it does

- Takes the game process to ring 0 through the `/dev/apm` clone UaF.
- Leaks the kernel base, walks `thread → proc → filedesc → fd_ofiles → file → ops`, widens the libc mapping, hooks `fo_ioctl` and plants a `syscall 11` kexec gate.
- Applies afterglow's 15 kernel patches plus GoldHEN's patch set, then rewrites `ucred` / `prison0` / `rootvnode` (`uid 0`).
- Tears its own handles down afterwards, so the process can exit cleanly.
- Runs GoldHEN: hands `goldhen.bin` to a small loader that starts it in a user thread, where it installs itself through the gate.

## Features

| Item | Detail |
|---|---|
| Firmware tables | **11**: 12.00 / 12.02 / 12.50 / 12.52 / 13.00 / 13.02 / 13.04 / 13.50 / 13.52 / 14.00 / 14.02 |
| Verified on hardware | FW **14.02** only |
| GoldHEN | official 298 KB `goldhen.bin` (flat image), installed over port 9020 |
| Gadget discovery | by content, no hardcoded offsets -- works on a different libc build too |
| Core pinning | measures every core, pins the fastest (13x difference between them) |
| Unknown firmware | refuses before firing: no shots spent, no crash, prints the supported list |
| Files written on the console | none |

## Requirements

1. An Artemis PS4 game that can load a **custom save**.
2. [remote_lua_loader](https://github.com/n0llptr/remote_lua_loader) running inside that game, listening on **9026**.
3. A PC on the same network (the scripts are PowerShell + Python).
4. Your own copy of official GoldHEN. It is not included in this repository.

## Quick start

```powershell
cd afterglow-lua
$IP = "XXX.XXX.X.XX"      # console IP

# 1. jailbreak; wait for "handles defused"
.\_test\setcfg.ps1 mode run
.\_test\send.ps1 -Ip $IP

# 2. start the installer; it waits on 9020, leave this window open
.\_test\setcfg.ps1 mode goldhen
.\_test\send.ps1 -Ip $IP

# 3. in a second window, push the payload
.\_test\send_bin.ps1 -Ip $IP -File .\payload\goldhen.bin
```

## Firmware support

| Firmware | Kernel table | Bootstrap | Patches | Patchset | Tested |
|---|---|---|---|---|---|
| 14.02 | ✅ | 142 B | 15 | 641 B | ✅ |
| 14.00 | ✅ | 142 B | 15 | 641 B | — |
| 13.52 | ✅ | 142 B | 15 | 632 B | — |
| 13.50 / 13.04 / 13.02 / 13.00 | ✅ | 142 B | 15 | 641 B | — |
| 12.52 / 12.50 / 12.02 / 12.00 | ✅ | 142 B | 15 | 641 B | — |

The firmware is read from the loader's `FW_VERSION`. `mode = "probe"` reports the firmware it detected and the list this build supports.

## Modes

Switch with `.\_test\setcfg.ps1 mode <name>`:

| Mode | What it does | Shots |
|---|---|---|
| `probe` | reads gadgets / units / kqueue / UDP / per-core cost, fires nothing (default) | 0 |
| `run` | the jailbreak | 4-5 |
| `goldhen` | waits on 9020 for `goldhen.bin` and runs it | 0 |
| `gate` | ring 0 proof: `rdmsr` on LSTAR plus a read of the kernel ELF header | 0 |
| `elf` | ELF loader self-test (build an image, map it, execute it) | 0 |
| `listen` / `flat` / `kexec` | earlier payload-forwarding paths, kept for comparison | 0 |

## Notes

- **After `run` alone, without GoldHEN, shutdown and restart hang.** The kernel patch turns `sysent[11]` into a kexec gate, and something in the shutdown path calls it. Hold the power button in that case.
- **Once GoldHEN is running, shutdown and restart are normal again** -- GoldHEN takes that syscall over.
- The jailbreak lives in RAM only; a reboot clears it, just run the three steps again.
- Each boot allows about 63 shots; `run` spends 4-5, every other mode spends none.

## How it works

```
[1]  leak kernel memory through the reclaimed object, locate the base
[2]  pick a cdev whose ops table lives in kernel text
[3]  thread → proc → filedesc → fd_ofiles → file → ops
[3b] walk vm_map for the mapping that covers the libc tail page
[4]  pick that mapping, read its protection
[5]  widen it to writable, hook fo_ioctl
[6]  ioctl() runs the bootstrap in ring 0; sysent[11] becomes a kexec gate
[7]  the gate provides kernel read/write (rep movsb inside a CR0.WP bracket)
[8]  15 kernel patches
[9]  ucred / prison0 / rootvnode → uid 0
[g]  GoldHEN patch set
[t]  rehang the ops tables, empty the kqueues, defuse the handles
```

Every instruction in these chains is a plain `mov` / `pop` / `add` / `ret`: ring 0 **must not call libc** here, because `memcpy` uses SSE while the kernel runs with `CR0.TS` set.

## Questions and feedback

Questions and pull requests are welcome.

## Credits

- **[well0nez](https://github.com/well0nez)** -- afterglow / afterglow-web: the kernel exploit, and the bulk of this project.
- **[n0llptr](https://github.com/n0llptr)** -- remote_lua_loader, the host this runs in.
- **[SiSTRo](https://github.com/SiSTR0)** and the [GoldHEN contributors](https://github.com/GoldHEN/GoldHEN) -- GoldHEN and its patch set.
- **raw13** -- the WebKit entry upstream descends from (see the [afterglow-web](https://github.com/well0nez/afterglow-web) notes).
- **[DeepSeek](https://www.deepseek.com)** -- AI assistant used during the port.

## Legal and license

AGPL-3.0, see `LICENSE`.

For study and research use only. Users must comply with their local laws; the author accepts no liability for any consequences.
