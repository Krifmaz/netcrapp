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
| LOG SENSE (temperature page only)| `0x4D` | drive temps; `SP` bit forced to 0      |

Never sent: SEND DIAGNOSTIC (no SES control pages), WRITE BUFFER / any
firmware operation, FORMAT, MODE SELECT, or any write to `/dev/sd*`. The
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

## Build

```sh
cargo build --release
# binaries: target/release/ds4246-ses, target/release/ds4246-web
```

## Running (needs root for /dev/sg*)

Root is required because `/dev/sg*` is `root:disk 0660` and SES commands need
`CAP_SYS_RAWIO`. Everything below only *reads* from the enclosure.

```sh
sudo ./target/release/ds4246-ses list            # find enclosures (type 0x0D)
sudo ./target/release/ds4246-ses scan            # summary + why the LED is on
sudo ./target/release/ds4246-ses dump            # ./dumps/<sgN>/<timestamp>/page_XX.{bin,txt}
./target/release/ds4246-ses decode dumps/sg5/<ts> # re-parse a saved dump, no root needed
```

### Web dashboard

```sh
./target/release/ds4246-web hash-password        # paste output into config
sudo ./target/release/ds4246-web --config deploy/config.example.toml
```

* Binds only to the address in the config; refuses `0.0.0.0`/`::` and
  public IPs unless `allow_non_lan = true`.
* Password login (argon2 hash), HttpOnly + SameSite=Strict session cookie.
* Plain HTTP — keep it on a trusted LAN/VLAN (or put a TLS proxy in front).
* `--replay <dump dir>` serves a saved dump instead of live hardware.

Install as a service: see `deploy/ds4246-web.service`.

## License

MIT — see `LICENSE`.
