//! Reading every page from an enclosure, and saving/loading dump sets.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::discover::SgInfo;
use crate::hexdump::hexdump;
use crate::scsi::IdentityRaw;
use crate::ses::{self, page_name, types::is_vendor_page};
use crate::sg::{self, SgDevice};

/// Pages re-read on every poll. Everything else is only read on a full read
/// (startup, CLI, "save dump"), in case a vendor page is read-and-clear.
pub const POLL_PAGES: &[u8] = &[0x01, 0x02, 0x07, 0x0A];
const ALLOC: u16 = 65532;

#[derive(Debug, Clone, Serialize)]
pub struct RawPage {
    pub code: u8,
    pub name: &'static str,
    pub vendor: bool,
    pub data: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl RawPage {
    fn new(code: u8, r: Result<Vec<u8>, String>) -> Self {
        let (data, error) = match r {
            Ok(d) => (Some(d), None),
            Err(e) => (None, Some(e)),
        };
        Self { code, name: page_name(code), vendor: is_vendor_page(code), data, error }
    }
}

/// Everything read from one enclosure device, unparsed.
#[derive(Debug, Clone, Serialize)]
pub struct EnclosureRead {
    pub device: String,
    pub hctl: Option<String>,
    pub read_at: DateTime<Utc>,
    /// True if every listed page was read (not just [`POLL_PAGES`]).
    pub full: bool,
    pub identity: IdentityRaw,
    pub supported: Vec<u8>,
    pub pages: Vec<RawPage>,
    pub errors: Vec<String>,
}

impl EnclosureRead {
    pub fn page(&self, code: u8) -> Option<&[u8]> {
        self.pages.iter().find(|p| p.code == code)?.data.as_deref()
    }

    pub fn vendor_pages(&self) -> Vec<u8> {
        self.supported.iter().copied().filter(|&p| is_vendor_page(p)).collect()
    }
}

fn receive(dev: &SgDevice, page: u8) -> Result<Vec<u8>, String> {
    let d = dev.read_cdb(&sg::receive_diag_cdb(page, ALLOC), ALLOC as usize).map_err(|e| e.to_string())?;
    if d.len() >= 4 {
        let want = 4 + u16::from_be_bytes([d[2], d[3]]) as usize;
        if want <= d.len() {
            return Ok(d[..want].to_vec());
        }
    }
    Ok(d)
}

pub fn read_enclosure(info: &SgInfo, full: bool) -> EnclosureRead {
    let mut r = EnclosureRead {
        device: info.name.clone(),
        hctl: info.hctl.clone(),
        read_at: Utc::now(),
        full,
        identity: IdentityRaw::default(),
        supported: Vec::new(),
        pages: Vec::new(),
        errors: Vec::new(),
    };
    let dev = match SgDevice::open(&info.dev_path) {
        Ok(d) => d,
        Err(e) => {
            r.errors.push(e.to_string());
            return r;
        }
    };
    if full {
        let (id, raw) = crate::scsi::read_identity(&dev);
        r.errors.extend(id.errors);
        r.identity = raw;
    }
    let p0 = receive(&dev, 0x00);
    match &p0 {
        Ok(d) => match ses::parse_supported(0x00, d) {
            Ok(list) => r.supported = list,
            Err(e) => r.errors.push(e.to_string()),
        },
        Err(e) => r.errors.push(format!("page 0x00: {e}")),
    }
    r.pages.push(RawPage::new(0x00, p0));
    let wanted: Vec<u8> = if full {
        r.supported.iter().copied().filter(|&p| p != 0x00).collect()
    } else if r.supported.is_empty() {
        POLL_PAGES.to_vec()
    } else {
        POLL_PAGES.iter().copied().filter(|p| r.supported.contains(p)).collect()
    };
    for code in wanted {
        let res = receive(&dev, code);
        if let Err(e) = &res {
            r.errors.push(format!("page {code:#04x}: {e}"));
        }
        r.pages.push(RawPage::new(code, res));
    }
    r
}

#[derive(Serialize, Deserialize)]
struct Meta {
    device: String,
    hctl: Option<String>,
    read_at: DateTime<Utc>,
    full: bool,
    supported: Vec<u8>,
    errors: Vec<String>,
    page_errors: Vec<(u8, String)>,
    vpd_errors: Vec<(u8, String)>,
}

fn write_pair(dir: &Path, stem: &str, title: &str, data: &[u8]) -> std::io::Result<()> {
    fs::write(dir.join(format!("{stem}.bin")), data)?;
    fs::write(dir.join(format!("{stem}.txt")), format!("# {title}\n# {} bytes\n{}", data.len(), hexdump(data)))
}

/// Writes `<root>/<device>/<timestamp>/` and returns that directory.
/// `summary` is the human-readable report saved alongside the raw pages.
pub fn save_dump(root: &Path, r: &EnclosureRead, summary: &str) -> std::io::Result<PathBuf> {
    let dir = root.join(&r.device).join(r.read_at.format("%Y-%m-%dT%H-%M-%SZ").to_string());
    fs::create_dir_all(&dir)?;
    if let Some(d) = &r.identity.inquiry {
        write_pair(&dir, "inquiry", "standard INQUIRY", d)?;
    }
    let mut vpd_errors = Vec::new();
    for (code, res) in &r.identity.vpd {
        match res {
            Ok(d) => write_pair(&dir, &format!("vpd_{code:02x}"), &format!("VPD page {code:#04x}"), d)?,
            Err(e) => vpd_errors.push((*code, e.clone())),
        }
    }
    let mut page_errors = Vec::new();
    for p in &r.pages {
        match (&p.data, &p.error) {
            (Some(d), _) => write_pair(&dir, &format!("page_{:02x}", p.code), &format!("SES page {:#04x} {}", p.code, p.name), d)?,
            (None, Some(e)) => page_errors.push((p.code, e.clone())),
            _ => {}
        }
    }
    let meta = Meta {
        device: r.device.clone(),
        hctl: r.hctl.clone(),
        read_at: r.read_at,
        full: r.full,
        supported: r.supported.clone(),
        errors: r.errors.clone(),
        page_errors,
        vpd_errors,
    };
    fs::write(dir.join("meta.json"), serde_json::to_string_pretty(&meta).unwrap_or_default())?;
    fs::write(dir.join("summary.txt"), summary)?;
    Ok(dir)
}

/// Loads a dump directory written by [`save_dump`] (or any directory of
/// `page_XX.bin` files) back into an [`EnclosureRead`].
pub fn load_dump(dir: &Path) -> std::io::Result<EnclosureRead> {
    let meta: Option<Meta> = fs::read_to_string(dir.join("meta.json")).ok().and_then(|s| serde_json::from_str(&s).ok());
    let mut pages = Vec::new();
    let mut vpd = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
        if p.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let parse_code = |prefix: &str| stem.strip_prefix(prefix).and_then(|h| u8::from_str_radix(h, 16).ok());
        if let Some(code) = parse_code("page_") {
            pages.push(RawPage::new(code, Ok(fs::read(&p)?)));
        } else if let Some(code) = parse_code("vpd_") {
            vpd.push((code, Ok(fs::read(&p)?)));
        }
    }
    let inquiry = fs::read(dir.join("inquiry.bin")).ok();
    let mut supported = pages.iter().find(|p| p.code == 0).and_then(|p| p.data.as_deref()).and_then(|d| ses::parse_supported(0, d).ok()).unwrap_or_default();
    if supported.is_empty() {
        supported = pages.iter().map(|p| p.code).collect();
    }
    let (device, hctl, read_at, full, errors) = match &meta {
        Some(m) => {
            for (c, e) in &m.page_errors {
                pages.push(RawPage::new(*c, Err(e.clone())));
            }
            (m.device.clone(), m.hctl.clone(), m.read_at, m.full, m.errors.clone())
        }
        None => (dir.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), None, Utc::now(), true, Vec::new()),
    };
    pages.sort_by_key(|p| p.code);
    Ok(EnclosureRead { device, hctl, read_at, full, identity: IdentityRaw { inquiry, vpd }, supported, pages, errors })
}
