# AmneziaWG for OpenBSD

Native kernel driver (`awg(4)`) for [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) — an obfuscated WireGuard fork — on OpenBSD 7.x amd64.

OpenBSD ships WireGuard (`wg(4)`) built into GENERIC. This project adds a parallel `awg(4)` pseudo-device to a custom kernel, providing the same 9 obfuscation parameters that AmneziaWG uses on Linux and Windows, without any userspace daemon.

AWG parameters are configured directly through `ifconfig(8)` — the same tool used for standard WireGuard on OpenBSD — with no external helper binary required.

## How it works

| Component | Role |
|-----------|------|
| `src/if_awg.c` | Kernel driver — clone of `if_wg.c` extended with AWG obfuscation |
| `src/if_awg.h` | Public ioctl interface (`SIOCSAWG`/`SIOCGAWG`, numbers 212/213) |
| `src/AWG.MP` | Kernel config (`include GENERIC.MP` + `pseudo-device awg`) |
| `sbin/ifconfig/ifconfig_awg.patch` | Patch for `/sbin/ifconfig` to add `awg*` flags |
| `sbin/awg-quick` | Shell script to bring tunnels up/down from a config file |
| `install.sh` | Build and install script |

Interfaces are named `awg0`, `awg1`, … Configs live in `/etc/amnezia/amneziawg/`.

## Requirements

- OpenBSD 7.x amd64
- Root access
- Packages: `bash` — `install.sh` installs it automatically
- Kernel sources and ifconfig sources — downloaded from the OpenBSD CDN automatically if missing

## Installation

```sh
git clone https://github.com/TrueBad0ur/awg-openbsd-kernel
cd awg-openbsd-kernel

# 1. Patch ifconfig + install awg-quick (fast, no reboot)
doas sh install.sh --tools-only

# 2. Build and install the AWG kernel (takes ~15 min, requires reboot)
doas sh install.sh --kernel-only

# Or do both in one shot:
doas sh install.sh --all
```

After `--kernel-only` or `--all`, reboot. The bootloader loads `/bsd` automatically.

```sh
reboot
```

Verify the kernel loaded and the device is available:

```sh
uname -v              # should show AWG.MP
ifconfig awg0 create  # should succeed
ifconfig awg0 destroy
```

## Usage

### Place your config

Config files go in `/etc/amnezia/amneziawg/`. The filename (without `.conf`) is the tunnel name.

```sh
doas mkdir -p /etc/amnezia/amneziawg
doas chmod 700 /etc/amnezia/amneziawg
doas cp myvpn.conf /etc/amnezia/amneziawg/
```

Config format is standard WireGuard + AWG obfuscation fields:

```ini
[Interface]
PrivateKey = <base64>
Address = 10.8.0.21/24
# AWG obfuscation parameters (provided by your server admin)
Jc = 4
Jmin = 10
Jmax = 50
S1 = 26
S2 = 33
H1 = 1737146616
H2 = 705704376
H3 = 391058102
H4 = 2103979647

[Peer]
PublicKey = <base64>
PresharedKey = <base64>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

If `Jc`–`H4` are all zero or absent, AWG behaves identically to standard WireGuard.

### Bring the tunnel up / down

```sh
doas awg-quick up myvpn
doas awg-quick down myvpn
```

`awg-quick` configures the tunnel entirely via `ifconfig`. If the config filename matches an `awgN` pattern (e.g. `awg0.conf`), that interface is used directly; otherwise the next free `awg0`, `awg1`, … is allocated.

### Inspect the tunnel

```sh
ifconfig awg0
```

Output includes all AWG parameters:

```
awg0: flags=80c3<UP,BROADCAST,RUNNING,NOARP,MULTICAST> mtu 1420
    awgport 51820
    awgpubkey <base64>
    awgjc 4 awgjmin 10 awgjmax 50
    awgs1 26 awgs2 33
    awgh1 1737146616 awgh2 705704376 awgh3 391058102 awgh4 2103979647
    awgpeer <base64>
        awgpsk (present)
        awgpka 25 (sec)
        awgendpoint 1.2.3.4 51820
        tx: 232408, rx: 67712
        last handshake: 3 seconds ago
        awgaip 0.0.0.0/0
    inet 10.8.0.21 netmask 0xffffff00 broadcast 10.8.0.255
```

### Manual configuration (without awg-quick)

Because AWG is fully integrated into `ifconfig`, you can configure interfaces manually:

```sh
ifconfig awg0 create
ifconfig awg0 awgkey <private-key-base64>
ifconfig awg0 awgport 51820
ifconfig awg0 awgjc 4 awgjmin 10 awgjmax 50
ifconfig awg0 awgs1 26 awgs2 33
ifconfig awg0 awgh1 1737146616 awgh2 705704376 awgh3 391058102 awgh4 2103979647
ifconfig awg0 awgpeer <peer-pubkey> awgpsk <psk> awgpka 25 \
         awgendpoint vpn.example.com 51820 awgaip 0.0.0.0/0
ifconfig awg0 inet 10.8.0.21/24
ifconfig awg0 up
```

This also means `/etc/hostname.awg0` works natively.

### Auto-start on boot

Via `/etc/hostname.awg0`:

```
awgkey <private-key-base64>
awgport 51820
awgjc 4 awgjmin 10 awgjmax 50
awgs1 26 awgs2 33
awgh1 1737146616 awgh2 705704376 awgh3 391058102 awgh4 2103979647
awgpeer <pubkey> awgpsk <psk> awgpka 25 awgendpoint vpn.example.com 51820 awgaip 0.0.0.0/0
inet 10.8.0.21/24
up
```

Or via `/etc/rc.local`:

```sh
awg-quick up myvpn
```

### TCP MSS clamping

`awg-quick` does not configure TCP MSS clamping automatically. Without it, TCP packets may exceed the tunnel MTU and get fragmented.

`install.sh` adds the following rule to `/etc/pf.conf` automatically:

```
match on awg scrub (max-mss 1380)
```

The value 1380 = tunnel MTU (1420) − IP header (20) − TCP header (20).

If you installed the tools manually, add this rule yourself and reload pf:

```sh
echo 'match on awg scrub (max-mss 1380)' >> /etc/pf.conf
pfctl -f /etc/pf.conf
```

## AWG obfuscation parameters

| Param | Meaning | Default (= plain WireGuard) |
|-------|---------|---------------------------|
| `Jc` | Number of junk packets sent before handshake | 0 |
| `Jmin` | Min size of each junk packet (bytes) | 0 |
| `Jmax` | Max size of each junk packet (bytes) | 0 |
| `S1` | Random prefix bytes prepended to Initiation packet | 0 |
| `S2` | Random prefix bytes prepended to Response packet | 0 |
| `H1` | Magic type header replacing packet type 1 (Initiation) | 1 |
| `H2` | Magic type header replacing packet type 2 (Response) | 2 |
| `H3` | Magic type header replacing packet type 3 (Cookie) | 3 |
| `H4` | Magic type header replacing packet type 4 (Data) | 4 |

Both endpoints must use the same values.

## Performance

Benchmarked on OpenBSD 7.9, AMD Ryzen 7 5800H, loopback (two interfaces on the same machine):

| Configuration | Throughput (single stream) | Throughput (4 streams) |
|---|---|---|
| WireGuard `wg(4)` baseline | 26.8 Gbps | 56.3 Gbps |
| AWG — no obfuscation | 27.9 Gbps | 56.0 Gbps |
| AWG — full obfuscation (Jc=4, S1=26, S2=33, custom H1–H4) | 26.9 Gbps | 56.3 Gbps |
| AWG — 30 AllowedIPs entries | 27.7 Gbps | — |

**AWG obfuscation adds zero measurable overhead on the data path.** The obfuscation parameters (junk packets, prefix bytes, magic headers) only affect handshake packets, not data encryption. AllowedIPs lookups use an ART (Allotment Routing Table) with O(prefix length) complexity, so the number of entries does not affect throughput or latency.

Real-world throughput is limited by the peer's bandwidth and RTT, not the driver.

## awg-quick internals

### No awg/wg tool dependency

The original `wg-quick` for OpenBSD (from amneziawg-tools) calls `wg setconf` to configure the interface and `wg show endpoints` to read back resolved peer endpoint IPs (the `wg` binary from amneziawg-tools is effectively `awg` added to PATH). This project eliminates that dependency entirely: `awg-quick` configures the interface via `ifconfig` and reads resolved endpoint IPs back from `ifconfig awg0` output (the kernel resolves hostnames at configuration time and exposes them as `awgendpoint IP PORT`).

### Peer endpoint host route

When `AllowedIPs` routes cover the peer endpoint IP, a routing loop forms: sending a WireGuard handshake packet to the peer requires going through the tunnel, but the tunnel cannot start without the handshake.

On Linux, WireGuard avoids this by marking its own UDP packets with `fwmark` and routing them through a separate routing table that bypasses `AllowedIPs` entirely. **OpenBSD has no equivalent `fwmark` mechanism.**

The standard `wg-quick` for OpenBSD addresses this only for the `AllowedIPs = 0.0.0.0/0` case (full routing): it adds a `/32` host route for each peer endpoint via the physical gateway before installing the tunnel routes. Because `/32` is more specific than any AllowedIPs prefix, it takes priority in the routing table and the tunnel's UDP packets reach the peer via the physical interface.

This project extends the same mechanism to **all routing configurations** — including split routing. After installing all AllowedIPs routes, `awg-quick` checks each peer endpoint IP with `route get`. If the result shows the tunnel interface, it installs a `/32` host route for that endpoint via the physical gateway. This correctly handles configs that route large public IP ranges through the tunnel while the peer endpoint IP happens to fall in one of those ranges.

## Why not just use the original AmneziaWG driver?

On **FreeBSD**, you can — there is an official `amnezia-kmod` package that installs a pre-built loadable kernel module (`if_amn.ko`), loaded at runtime via `kldload` without any reboot. See [freebsd-amneziawg-setup](https://github.com/HugoFiermein/freebsd-amneziawg-setup) for a ready-made installer.

On **OpenBSD**, this is not possible. OpenBSD does not support loadable kernel modules for network drivers — the kernel is monolithic and all pseudo-devices must be compiled in. The upstream `wg(4)` driver is compiled directly into `GENERIC`, not shipped as a `.ko`. There is no AmneziaWG package for OpenBSD and no shortcut: the only way is to fork `if_wg.c`, extend it with AWG obfuscation, and build a custom kernel. That is exactly what this project does.

As of 2026, **this is the only native kernel-level AmneziaWG implementation for OpenBSD**.

## Repo layout

```
src/                              kernel driver files
  if_awg.c                        AWG pseudo-device driver
  if_awg.h                        public ioctl interface
  AWG.MP                          kernel configuration
sbin/
  awg-quick                       tunnel up/down script (uses ifconfig only)
  ifconfig/
    ifconfig_awg.patch            patch for /sbin/ifconfig to add awg* flags
awg-openbsd.patch                 unified diff of all kernel changes
install.sh                        build + install script
```
