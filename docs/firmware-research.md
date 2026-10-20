# IOM6E firmware — public information (researched 2026-10-20)

Your modules report `DS424IOM6E`: the **IOM6E** line, which has its own
firmware files (`IOM6E.<rev>.SFW`), separate from plain IOM6 (`IOM6.<rev>.SFW`).

| Line  | Versions seen in public sources                         | Notes |
|-------|---------------------------------------------------------|-------|
| IOM6E | 0113, 0122, 0131 (2013), 0142, …, **0171, 0172**        | `IOM6E.0172.SFW` is named in a NetApp KB; nothing newer found |
| IOM6  | … 0173 (2014), … **0211** (called "current and likely last") | not for IOM6E |

* No newer IOM6E release than **0172** turned up. IOM B is probably already
  on the latest; IOM A (0171) is one behind.
* No separate ACP firmware exists for IOM6E (NetApp community).
* Official distribution: NetApp Support Site → Downloads → Disk Shelf
  Firmware (`all_shelf_fw.zip`), login + support entitlement required; also
  bundled in ONTAP releases. Applied by ONTAP (`storage shelf firmware update
  -module-type IOM6E`), firmware may be updated without an ONTAP upgrade.
* No public, documented Linux/sg3_utils procedure. The shelf's page 0x0E
  advertises download microcode via buffer ID 0, max 3 MiB — the standard
  SES/WRITE BUFFER download path exists, untested on IOM6E.
* Some packages also need an `.SFW.FVF` companion file (IBM N series notes).

Sources: NetApp KB "EMS reports Download failed on IOM6E.0172.SFW…",
NetApp Community "Updating IOM6", "IOMs", "Unable to update ACP…",
NetApp SAS Disk Shelves Installation and Service Guide, ONTAP CLI
`storage shelf firmware update`, IBM N series Disk Shelf Firmware Matrix /
Publication Matrix / download instructions.

## Big correction: these modules are FAS2552/FAS2554 controllers

* Both "IOMs" report `PN=111-01324` in their descriptors. Resellers list
  111-01324 as the **FAS2552 / FAS2554 controller module**.
* NetApp KB "How do shelf product IDs and modules in ONTAP map…": a
  **DS4246 with IOM6E** is how ONTAP reports the **embedded shelf of a
  FAS2554 / FAS2240-4**. A NetApp staffer calls these modules "PCMs, or
  confusingly, IOM6Es"; converting to a plain shelf means swapping them for
  IOM6 modules.
* So each module is a full controller (CPU, RAM, boot media, service
  processor, console port, e0M) with an embedded SAS expander that presents
  the SES device we have been reading.
* `IOM6.0211` is for the standalone IOM6 module (111-00190) and does not
  apply.
* Likely explanation for PHY 0–3 flapping: the controller's own SAS HBA
  attaches to its embedded expander on those PHYs, and the link comes up and
  drops as the controller repeatedly initialises/resets (boot loop or
  LOADER retries). Unconfirmed — the serial console or SP will show it.
* The ONTAP image on each controller's boot media normally carries the shelf
  firmware set (incl. IOM6E), so the image may already be on hardware you own.
* OM=/EM= descriptor fields are likely the e0M / service processor MACs.
