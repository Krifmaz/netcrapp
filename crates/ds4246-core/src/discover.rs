//! Device discovery through sysfs (read-only file reads, no shelling out).

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

const SG_CLASS: &str = "/sys/class/scsi_generic";
const ENCLOSURE_CLASS: &str = "/sys/class/enclosure";

#[derive(Debug, Clone, Serialize)]
pub struct SgInfo {
    /// e.g. "sg5"
    pub name: String,
    pub dev_path: PathBuf,
    /// H:C:T:L
    pub hctl: Option<String>,
    pub device_type: Option<u8>,
    pub vendor: String,
    pub model: String,
    pub rev: String,
    /// Block device name (e.g. "sdc") if any.
    pub block: Option<String>,
    pub sas_address: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub sg: String,
    pub block: Option<String>,
    pub hctl: Option<String>,
    pub vendor: String,
    pub model: String,
    /// Vendor + model joined the way the drive reports them; for SATA drives
    /// behind a translation layer this rebuilds the full ATA model string.
    pub display_model: String,
    pub rev: String,
    pub serial: Option<String>,
    pub size_bytes: Option<u64>,
    pub sas_address: Option<String>,
    pub temperature_c: Option<u8>,
    /// (enclosure H:C:T:L, slot) according to the kernel `ses` driver, if loaded.
    pub kernel_slot: Option<(String, u32)>,
}

fn read_trim(p: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn link_name(p: impl AsRef<Path>) -> Option<String> {
    fs::canonicalize(p).ok()?.file_name()?.to_str().map(str::to_string)
}

/// Normalises a SAS address to 16 lowercase hex digits.
pub fn norm_sas(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_ascii_lowercase()
}

pub fn list_sg() -> Vec<SgInfo> {
    let Ok(rd) = fs::read_dir(SG_CLASS) else { return Vec::new() };
    let mut out: Vec<SgInfo> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let dev = e.path().join("device");
            let block = fs::read_dir(dev.join("block")).ok().and_then(|mut r| r.next()).and_then(|b| b.ok()).and_then(|b| b.file_name().to_str().map(str::to_string));
            Some(SgInfo {
                dev_path: PathBuf::from("/dev").join(&name),
                hctl: link_name(&dev),
                device_type: read_trim(dev.join("type")).and_then(|t| t.parse().ok()),
                vendor: read_trim(dev.join("vendor")).unwrap_or_default(),
                model: read_trim(dev.join("model")).unwrap_or_default(),
                rev: read_trim(dev.join("rev")).unwrap_or_default(),
                block,
                sas_address: read_trim(dev.join("sas_address")).map(|s| norm_sas(&s)),
                name,
            })
        })
        .collect();
    out.sort_by_key(|s| s.name.trim_start_matches("sg").parse::<u32>().unwrap_or(u32::MAX));
    out
}

/// Enclosure services devices: peripheral device type 0x0D.
pub fn enclosures() -> Vec<SgInfo> {
    list_sg().into_iter().filter(|s| s.device_type == Some(0x0D)).collect()
}

/// Kernel `ses` driver view: disk H:C:T:L -> (enclosure H:C:T:L, slot).
fn kernel_slots() -> Vec<(String, String, u32)> {
    let mut out = Vec::new();
    let Ok(encs) = fs::read_dir(ENCLOSURE_CLASS) else { return out };
    for enc in encs.flatten() {
        let enc_name = enc.file_name().to_string_lossy().to_string();
        let Ok(comps) = fs::read_dir(enc.path()) else { continue };
        for c in comps.flatten() {
            let p = c.path();
            let (Some(slot), Some(disk)) = (read_trim(p.join("slot")).and_then(|s| s.parse().ok()), link_name(p.join("device"))) else {
                continue;
            };
            out.push((disk, enc_name.clone(), slot));
        }
    }
    out
}

/// Disks (type 0x00) with model/serial from sysfs. Temperatures are filled in
/// separately because they need a SCSI command.
pub fn disks() -> Vec<DiskInfo> {
    let slots = kernel_slots();
    list_sg()
        .into_iter()
        .filter(|s| s.device_type == Some(0x00))
        .map(|s| {
            let dev = Path::new(SG_CLASS).join(&s.name).join("device");
            let serial = fs::read(dev.join("vpd_pg80")).ok().map(|d| crate::scsi::parse_vpd_serial(&d)).filter(|s| !s.is_empty());
            let size_bytes = s.block.as_ref().and_then(|b| read_trim(format!("/sys/block/{b}/size"))).and_then(|v| v.parse::<u64>().ok()).map(|n| n * 512);
            let kernel_slot = s.hctl.as_ref().and_then(|h| slots.iter().find(|(d, _, _)| d == h)).map(|(_, e, n)| (e.clone(), *n));
            let raw_vendor = fs::read_to_string(dev.join("vendor")).unwrap_or_default();
            let raw_model = fs::read_to_string(dev.join("model")).unwrap_or_default();
            DiskInfo {
                display_model: display_model(&raw_vendor, &raw_model),
                temperature_c: s.block.as_ref().and_then(|b| hwmon_temp(b)),
                sg: s.name,
                block: s.block,
                hctl: s.hctl,
                vendor: s.vendor,
                model: s.model,
                rev: s.rev,
                serial,
                size_bytes,
                sas_address: s.sas_address,
                kernel_slot,
            }
        })
        .collect()
}

/// INQUIRY splits a SATA model across the 8-byte vendor and 16-byte product
/// fields (e.g. "ST2000LM" + "007-1R8174"), so join the raw padded fields.
pub fn display_model(raw_vendor: &str, raw_model: &str) -> String {
    let v = raw_vendor.trim_end_matches('\n');
    let v = format!("{v:<8}");
    let joined = format!("{}{}", &v[..8.min(v.len())], raw_model.trim_end_matches('\n'));
    let collapsed = joined.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.strip_prefix("ATA ").map(str::to_string).unwrap_or(collapsed)
}

/// `drivetemp` hwmon reading, if that module is loaded.
fn hwmon_temp(block: &str) -> Option<u8> {
    let dir = fs::read_dir(format!("/sys/block/{block}/device/hwmon")).ok()?;
    for h in dir.flatten() {
        if let Some(milli) = read_trim(h.path().join("temp1_input")).and_then(|v| v.parse::<i64>().ok()) {
            return u8::try_from(milli / 1000).ok();
        }
    }
    None
}

/// Fills missing disk temperatures with LOG SENSE page 0x0D (read-only).
pub fn fill_temperatures(disks: &mut [DiskInfo]) {
    for d in disks.iter_mut().filter(|d| d.temperature_c.is_none()) {
        if let Ok(dev) = crate::sg::SgDevice::open(Path::new("/dev").join(&d.sg)) {
            d.temperature_c = crate::scsi::read_drive_temperature(&dev).ok().flatten();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::display_model;

    #[test]
    fn sata_model_join() {
        assert_eq!(display_model("ST2000LM\n", "007-1R8174    SM\n"), "ST2000LM007-1R8174 SM");
        assert_eq!(display_model("WDC     \n", "WD7500BPKT-75PSM\n"), "WDC WD7500BPKT-75PSM");
        assert_eq!(display_model("ATA     \n", "ST4000NM0033-9ZM\n"), "ST4000NM0033-9ZM");
        assert_eq!(display_model("SEAGATE \n", "ST4000NM0023    \n"), "SEAGATE ST4000NM0023");
    }
}
