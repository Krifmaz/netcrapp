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
