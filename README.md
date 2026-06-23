# AmneziaWG for OpenBSD

Native kernel driver (`awg(4)`) for [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) — an obfuscated WireGuard fork — on OpenBSD 7.x amd64.

OpenBSD ships WireGuard (`wg(4)`) built into GENERIC. This project adds a parallel `awg(4)` pseudo-device to a custom kernel, providing the same 9 obfuscation parameters that AmneziaWG uses on Linux and Windows, without any userspace daemon.

## How it works

| Component | Role |
|-----------|------|
| `src/if_awg.c` | Kernel driver — clone of `if_wg.c` extended with AWG obfuscation |
| `src/if_awg.h` | Public ioctl interface (`SIOCSAWG`/`SIOCGAWG`, numbers 212/213) |
| `src/AWG.MP` | Kernel config (`include GENERIC.MP` + `pseudo-device awg`) |
| `dependencies/amneziawg-tools` | `awg` + `awg-quick` CLI tools patched for `awg*` interfaces |
| `install.sh` | Build and install script |

Interfaces are named `awg0`, `awg1`, … Configs live in `/etc/amnezia/amneziawg/`.

## Requirements

- OpenBSD 7.x amd64
- Root access
- Kernel sources at `/usr/src/sys/` — `install.sh` downloads `sys.tar.gz` from the OpenBSD CDN automatically if missing
- Packages: `bash`, `coreutils` (ginstall), `gmake` — `install.sh` installs them automatically

## Installation

```sh
# Clone the repo with submodules
git clone --recurse-submodules https://github.com/TrueBad0ur/awg-openbsd-kernel
cd awg-openbsd-kernel

# 1. Build and install awg + awg-quick tools (fast, no reboot)
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

`awg-quick` allocates the next free `awg0`, `awg1`, … kernel interface automatically. The config name (`myvpn`) is stored as the interface description so it can be found again on `down`.

### Inspect the tunnel

```sh
awg show          # all AWG interfaces
awg show awg0     # specific interface — shows jc/jmin/jmax/s1/s2/h1-h4, peers, handshake time, bytes
ifconfig awg0     # IP/routing info
```

### Auto-start on boot

Add to `/etc/rc.local`:

```sh
awg-quick up myvpn
```

### TCP MSS clamping

`awg-quick` does not configure TCP MSS clamping automatically (unlike Linux `wg-quick`). Without it, TCP packets may exceed the tunnel MTU and get fragmented.

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

## Applying the patch to a new machine

```sh
cd /usr/src/sys
patch -p0 < /path/to/awg-openbsd.patch

cd arch/amd64/conf
config AWG.MP

cd ../compile/AWG.MP
make -j$(sysctl -n hw.ncpu) && make install
reboot
```

## Performance

Benchmarked on OpenBSD 7.9, AMD Ryzen 7 5800H, loopback (two interfaces on the same machine):

| Configuration | Throughput (single stream) | Throughput (4 streams) |
|---|---|---|
| WireGuard `wg(4)` baseline | 26.8 Gbps | 56.3 Gbps |
| AWG — no obfuscation | 27.9 Gbps | 56.0 Gbps |
| AWG — full obfuscation (Jc=4, S1=26, S2=33, custom H1–H4) | 26.9 Gbps | 56.3 Gbps |
| AWG — 30 AllowedIPs entries | 27.7 Gbps | — |

**AWG obfuscation adds zero measurable overhead on the data path.** The obfuscation parameters (junk packets, prefix bytes, magic headers) only affect handshake packets, not data encryption. AllowedIPs lookups use an ART (Allotment Routing Table) with O(prefix length) complexity, so the number of entries does not affect throughput or latency.

Real-world tunnel to a remote peer (~37 ms RTT), measured with `curl` against Cloudflare:

| Direction | Speed |
|---|---|
| Download | 61.7 Mbit/s |
| Upload | 78.0 Mbit/s |
| Latency | ~20 ms |

These numbers are limited by the peer's bandwidth and the RTT, not the driver.

## Why not just use the original AmneziaWG driver?

On **FreeBSD**, you can — there is an official `amnezia-kmod` package that installs a pre-built loadable kernel module (`if_amn.ko`), loaded at runtime via `kldload` without any reboot. See [freebsd-amneziawg-setup](https://github.com/HugoFiermein/freebsd-amneziawg-setup) for a ready-made installer.

On **OpenBSD**, this is not possible. OpenBSD does not support loadable kernel modules for network drivers — the kernel is monolithic and all pseudo-devices must be compiled in. The upstream `wg(4)` driver is compiled directly into `GENERIC`, not shipped as a `.ko`. There is no AmneziaWG package for OpenBSD and no shortcut: the only way is to fork `if_wg.c`, extend it with AWG obfuscation, and build a custom kernel. That is exactly what this project does.

As of 2026, **this is the only native kernel-level AmneziaWG implementation for OpenBSD**. The only prior alternative was the userspace daemon `amneziawg-go`, which trades kernel performance for portability.

## Repo layout

```
src/                  kernel driver files
  if_awg.c            AWG pseudo-device driver
  if_awg.h            public ioctl interface
  AWG.MP              kernel configuration
dependencies/
  amneziawg-tools/    awg + awg-quick CLI (git submodule)
awg-openbsd.patch     unified diff of all kernel changes (patch -p0 from /usr/src/sys)
install.sh            build + install script
```
