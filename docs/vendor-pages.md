# DS4246 / IOM6E vendor SES pages — working notes

Firmware 0172 (IOM B) / 0171 (IOM A). Hypotheses only; each needs a
before/after dump to confirm. No raw dumps or identifiers are kept here.

All four pages share the SES header: page code, reserved, 2-byte page length,
4-byte generation code (same value as pages 0x01/0x02).

## 0x80 and 0x81 — per-PHY table (1020 bytes each)

* Bytes 8–9: unknown (`dc 24` on 0x80, `49 24` on 0x81).
* From byte 12: **36 records × 28 bytes**, record `n` at `12 + 28·n`.
  36 matches the PHY count of the IOM6 SAS expander.

| Offset | Meaning (hypothesis)                                              |
|--------|-------------------------------------------------------------------|
| 0      | PHY number 0x00–0x23                                              |
| 1      | state/reason when the link is down (`00` when up; seen `12 21 60`)|
| 2      | high nibble = negotiated rate (`a` = 6 Gbit/s, `0` = no link); low nibble always `7` |
| 3–25   | mostly zero; PHY 3 has `0x12` at +7 and +11 (error counters?)     |
| 26–27  | big-endian counter (2071 on host-port PHYs, 1–10 on drive PHYs: link resets / PHY change count?) |

Observed on 2026-10-20 with 9 drives in bays 0–8, host cabled to IOM B only:

* 0x80: PHYs 0x00–0x10 at 6 Gbit/s; 0x11–0x1F down (`21`), 0x20–0x23 down (`60`).
* 0x81: PHYs 0x00–0x03 down (`12`), 0x04–0x07 down (`21`), 0x08–0x10 up, rest as 0x80.
* Reading: PHYs 0x08–0x1F are the 24 drive bays (bays 0–8 → PHYs 0x08–0x10);
  0x80 is the answering IOM (B) and 0x81 its partner (A), whose host-side
  PHYs are down because A is not cabled.

**Confirmed 2026-10-20 (remotely, via sysfs):** the kernel's SAS topology puts
bay *N* on expander PHY `8 + N` for all nine populated bays (sda bay 0 → phy 8 …
sdc bay 8 → phy 16). So records 0x08–0x1F are drive bays 0–23.

Two dumps 14 minutes apart (13:19 → 13:33 UTC):

* bytes 8–9: `dc 24` → `0b 24` — first byte changes, second fixed (tick/sequence?).
* host-port PHYs 0–3: counter +6 on every lane (2071→2077, 2075→2081).
* PHYs 4–7 and all drive PHYs: unchanged.

Equal steps on all four lanes of the wide port point to port-level events
(link reset of the whole port, or BROADCAST(CHANGE) handling) rather than
per-lane bit errors. Next check: compare with `mpt2sas`/`mpt3sas` lines in
`dmesg` for the same window.

## 0x82 and 0x83 — identical 160-byte tables

After the 8-byte header: 8 zero bytes, then three 24-byte blocks, each
`3f 00 3c 3c 00 78 00 78 00 78 00 3c 00 3c 00 78` + 8 zero bytes.
`0x3c` = 60, `0x78` = 120 — look like timer/threshold settings in seconds,
`0x3f` a 6-bit enable mask. No fault data visible. One page per IOM?

## Fault LED

No vendor page shows an obvious fault code. The only non-OK state in the
standard pages is the Enclosure element's FAILURE INDICATION, and the IOM
element descriptors show FW=0172 (B) vs FW=0171 (A) — the leading
explanation for the latched LED.
