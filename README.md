# netcrapp — NetApp DS4246 control without NetApp

Reverse engineering a secondhand NetApp DS4246 disk shelf over **SES**
(SCSI Enclosure Services), talking to it directly with the Linux `SG_IO`
ioctl from Rust. No NetApp software, no support contract.

## Hardware

| Part        | Detail                                                    |
|-------------|-----------------------------------------------------------|
| Shelf       | NetApp DS4246, 24 × 3.5" bays (4 rows × 6), 4 PSU bays    |
| Controllers | 2 × IOM6 (running *different* firmware versions)          |
| HBA         | LSI 9206-16e, IT mode                                     |
| Host        | Proxmox VE (production hypervisor)                        |
| Drives      | Mostly Seagate, already 512-byte sectors                  |

Known symptoms: front amber fault LED stays on (even with one IOM and all
PSUs in), shelf ID shows a solid `0`, fans never ramp down.

## Goal

Full, documented control of the shelf from Linux:

1. **Phase 1 — read-only mapping (current).** Enumerate the enclosure(s),
   read every SES diagnostic page (vendor pages included), parse the
   standard ones, explain *why* the fault LED is on, and save raw dumps for
   reverse engineering. Web dashboard + small debug CLI.
2. **Phase 2 — SES control.** Fan speed, drive LEDs, clearing the fault.
   *(not started; UI slots exist but are disabled)*
3. **Phase 3 — IOM firmware.** Dump with READ BUFFER and analyse.
   *(not started)*

## Safety rules (Phase 1)

The tool is **read-only by construction**: every CDB goes through one
function (`ds4246_core::sg`) that only accepts an allow-list of opcodes and
always uses data-in (device → host) transfers.

| Allowed                          | Opcode | Notes                                  |
|----------------------------------|--------|----------------------------------------|
| INQUIRY (std + VPD)              | `0x12` |                                        |
| RECEIVE DIAGNOSTIC RESULTS       | `0x1C` | reads SES pages                        |
| LOG SENSE (temperature page)     | `0x4D` | drive temps; `SP` (save) bit refused   |
| READ BUFFER (Phase 3)            | `0x3C` | modes 02h (data) and 03h (descriptor) only |

Never sent: SEND DIAGNOSTIC (no SES control pages), WRITE BUFFER / any
firmware write or download, FORMAT, MODE SELECT, or any write to `/dev/sd*`. The
tools do not touch Proxmox config, VMs or storage.

Repository rules: raw dumps, serial numbers, WWNs / SAS addresses and
anything from NetApp firmware are **never committed** (`/dumps` is
git-ignored).

## Layout

```
crates/
  ds4246-core   library: SG_IO, INQUIRY/VPD, SES page parsers, fault analysis, dumps
  ds4246-ses    debug CLI: list / scan / dump / decode
  ds4246-web    axum dashboard (main interface), single self-contained binary
deploy/         systemd unit + example config
```

## Install (prebuilt, recommended for the Proxmox host)

Releases ship static x86_64 binaries built by GitHub Actions, so the host
needs only `curl` — no Rust, git or apt packages:

```sh
V=v0.1.0   # release tag
curl -fsSLO https://github.com/Krifmaz/netcrapp/releases/download/$V/netcrapp-$V-linux-amd64.tar.gz
curl -fsSL https://github.com/Krifmaz/netcrapp/releases/download/$V/SHA256SUMS | sha256sum -c --ignore-missing
tar xzf netcrapp-$V-linux-amd64.tar.gz && cd netcrapp-$V-linux-amd64
```

## Build from source

Needs a Rust toolchain (`rustup`, installs to `~/.cargo`, no system packages).
Build on the Proxmox host, or on any Debian box with the same or older glibc
and copy the binaries over.

```sh
cargo build --release
# target/release/ds4246-ses   (debug CLI)
# target/release/ds4246-web   (dashboard)
cargo test                    # parsers are tested against synthetic pages
```

## Step 1 on the host — confirm the enclosures exist

Optional cross-check with standard tools (`apt install lsscsi sg3-utils` if
missing — ask/decide before installing on the hypervisor):

```sh
lsscsi -g                 # look for "enclosu NETAPP DS424IOM6 ... /dev/sgN"
sudo sg_ses -p 0x0 /dev/sgN
```

The same, without any packages:

```sh
sudo ./target/release/ds4246-ses list     # sysfs only, no SCSI commands
```

## CLI (needs root for /dev/sg*)

`/dev/sg*` is `root:disk 0660` and SES pass-through needs `CAP_SYS_RAWIO`.
Every command below only *reads*.

```sh
sudo ./target/release/ds4246-ses scan              # INQUIRY + VPD 00/80/83 + every SES page listed
                                                   # in page 0x00 → summary + why the LED is on
sudo ./target/release/ds4246-ses scan --json       # full parsed snapshot
sudo ./target/release/ds4246-ses dump              # same + ./dumps/<sgN>/<timestamp>/
./target/release/ds4246-ses decode dumps/sgN/<ts>  # re-parse a saved dump offline, no root
./target/release/ds4246-ses demo                   # synthetic data, no hardware
```

Phase 3 — read IOM firmware (read-only; images are never committed):

```sh
./ds4246-ses fw probe sg0                 # buffer IDs + sizes (mode 03h)
./ds4246-ses fw read sg0 --id <ID>        # reads it twice, saves dumps/sg0/<ts>/fw/ + report
./ds4246-ses fw analyze <file.bin>        # entropy map, signatures, version strings
```

A dump directory contains `inquiry.{bin,txt}`, `vpd_XX.{bin,txt}`,
`page_XX.{bin,txt}` for every page (vendor pages included), `meta.json`
(page list + read errors) and `summary.txt`.

## Web dashboard

```sh
./target/release/ds4246-web hash-password          # prints password_hash = "..."
sudo install -d -m 700 /etc/ds4246-web
sudo install -m 600 deploy/config.example.toml /etc/ds4246-web/config.toml   # edit bind + hash
sudo ./target/release/ds4246-web                   # or: --config path, --bind 192.168.1.10:8446
./target/release/ds4246-web -c cfg.toml --demo     # synthetic data
./target/release/ds4246-web -c cfg.toml --replay dumps/sgN/<ts>   # serve a saved dump
```

Tabs: **Dashboard** (front view of the 24 bays with status/model/temp, fault
LED explanation, IOMs + firmware, PSUs, fans with speed code/RPM,
temperatures, voltages), **All elements** (every element, raw status bytes),
**Raw pages** (hex of every page incl. vendor pages, `.bin` download),
**Controls** (Phase 2 placeholders, disabled — no control routes exist).

* Pages 0x01/0x02/0x07/0x0A are polled every `poll_secs`; all other pages are
  read only on start, **Full re-read** and **Save dump** (in case a vendor page
  is read-and-clear).
* Binds only to the configured address; refuses `0.0.0.0`/`::` and public IPs
  unless `allow_non_lan = true`.
* Password login (argon2), HttpOnly + SameSite=Strict cookie, CSRF header on
  POSTs, 5-minute lockout after 10 bad passwords, strict CSP.
* Plain HTTP — keep it on a trusted LAN/VLAN or put a TLS proxy in front.

### systemd

```sh
sudo install -m 755 target/release/ds4246-web /usr/local/bin/
sudo install -m 644 deploy/ds4246-web.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ds4246-web
```

The unit runs as root but keeps only `CAP_SYS_RAWIO`, a read-only filesystem
(except `/var/lib/ds4246-web`) and read-only access to `/dev/sg*` only.

## License

GPL-3.0 — see `LICENSE`.
