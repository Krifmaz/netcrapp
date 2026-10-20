//! INQUIRY / VPD / LOG SENSE parsing (SPC-5).

use serde::Serialize;

use crate::sg::{self, SgDevice, SgError};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Inquiry {
    pub peripheral_qualifier: u8,
    pub device_type: u8,
    pub version: u8,
    pub encserv: bool,
    pub vendor: String,
    pub product: String,
    pub revision: String,
    /// Bytes 36..56, often used by vendors for extra version info.
    pub vendor_specific: String,
}

pub fn ascii(b: &[u8]) -> String {
    let s: String = b.iter().map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { ' ' }).collect();
    s.trim().to_string()
}

pub fn parse_inquiry(d: &[u8]) -> Option<Inquiry> {
    if d.len() < 36 {
        return None;
    }
    Some(Inquiry {
        peripheral_qualifier: d[0] >> 5,
        device_type: d[0] & 0x1F,
        version: d[2],
        encserv: d[6] & 0x40 != 0,
        vendor: ascii(&d[8..16]),
        product: ascii(&d[16..32]),
        revision: ascii(&d[32..36]),
        vendor_specific: ascii(d.get(36..56.min(d.len())).unwrap_or(&[])),
    })
}

pub fn parse_vpd_supported(d: &[u8]) -> Vec<u8> {
    vpd_payload(d).to_vec()
}

pub fn parse_vpd_serial(d: &[u8]) -> String {
    ascii(vpd_payload(d))
}

fn vpd_payload(d: &[u8]) -> &[u8] {
    if d.len() < 4 {
        return &[];
    }
    let len = u16::from_be_bytes([d[2], d[3]]) as usize;
    &d[4..(4 + len).min(d.len())]
}

#[derive(Debug, Clone, Serialize)]
pub struct Designator {
    pub association: &'static str,
    pub kind: &'static str,
    pub value: String,
}

pub fn parse_vpd_device_id(d: &[u8]) -> Vec<Designator> {
    let mut out = Vec::new();
    let p = vpd_payload(d);
    let mut i = 0;
    while i + 4 <= p.len() {
        let code_set = p[i] & 0x0F;
        let assoc = (p[i + 1] >> 4) & 0x03;
        let dtype = p[i + 1] & 0x0F;
        let len = p[i + 3] as usize;
        let Some(body) = p.get(i + 4..i + 4 + len) else { break };
        let value = match (dtype, code_set) {
            (4, _) if body.len() >= 4 => format!("{}", u16::from_be_bytes([body[2], body[3]])),
            (_, 2) | (_, 3) => ascii(body),
            _ => body.iter().map(|b| format!("{b:02x}")).collect(),
        };
        out.push(Designator {
            association: match assoc {
                0 => "logical unit",
                1 => "target port",
                2 => "target device",
                _ => "reserved",
            },
            kind: match dtype {
                0 => "vendor specific",
                1 => "T10 vendor id",
                2 => "EUI-64",
                3 => "NAA",
                4 => "relative target port",
                5 => "target port group",
                6 => "logical unit group",
                7 => "MD5 LU id",
                8 => "SCSI name string",
                9 => "protocol specific port",
                _ => "reserved",
            },
            value,
        });
        i += 4 + len;
    }
    out
}

/// Raw responses captured for an enclosure, kept for the dump files.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IdentityRaw {
    pub inquiry: Option<Vec<u8>>,
    pub vpd: Vec<(u8, Result<Vec<u8>, String>)>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Identity {
    pub inquiry: Option<Inquiry>,
    pub vpd_pages: Vec<u8>,
    pub serial: Option<String>,
    pub designators: Vec<Designator>,
    pub errors: Vec<String>,
}

pub fn read_identity(dev: &SgDevice) -> (Identity, IdentityRaw) {
    let mut id = Identity::default();
    let mut raw = IdentityRaw::default();
    match dev.read_cdb(&sg::inquiry_cdb(None, 96), 96) {
        Ok(d) => {
            id.inquiry = parse_inquiry(&d);
            raw.inquiry = Some(d);
        }
        Err(e) => id.errors.push(format!("INQUIRY: {e}")),
    }
    for page in [0x00u8, 0x80, 0x83] {
        let r = dev.read_cdb(&sg::inquiry_cdb(Some(page), 1024), 1024);
        match &r {
            Ok(d) => match page {
                0x00 => id.vpd_pages = parse_vpd_supported(d),
                0x80 => id.serial = Some(parse_vpd_serial(d)),
                _ => id.designators = parse_vpd_device_id(d),
            },
            Err(e) => id.errors.push(format!("VPD {page:#04x}: {e}")),
        }
        raw.vpd.push((page, r.map_err(|e: SgError| e.to_string())));
    }
    (id, raw)
}

pub fn identity_from_raw(raw: &IdentityRaw) -> Identity {
    let mut id = Identity { inquiry: raw.inquiry.as_deref().and_then(parse_inquiry), ..Default::default() };
    for (page, r) in &raw.vpd {
        if let Ok(d) = r {
            match page {
                0x00 => id.vpd_pages = parse_vpd_supported(d),
                0x80 => id.serial = Some(parse_vpd_serial(d)),
                0x83 => id.designators = parse_vpd_device_id(d),
                _ => {}
            }
        }
    }
    id
}

/// Current temperature from the Temperature log page (0x0D), param 0x0000.
pub fn parse_log_temperature(d: &[u8]) -> Option<u8> {
    if d.len() < 4 || d[0] & 0x3F != 0x0D {
        return None;
    }
    let end = (4 + u16::from_be_bytes([d[2], d[3]]) as usize).min(d.len());
    let mut i = 4;
    while i + 4 <= end {
        let code = u16::from_be_bytes([d[i], d[i + 1]]);
        let len = d[i + 3] as usize;
        if code == 0 && len >= 2 && i + 6 <= end {
            let t = d[i + 5];
            return (t != 0xFF).then_some(t);
        }
        i += 4 + len;
    }
    None
}

pub fn read_drive_temperature(dev: &SgDevice) -> Result<Option<u8>, SgError> {
    let d = dev.read_cdb(&sg::log_sense_cdb(0x0D, 64), 64)?;
    Ok(parse_log_temperature(&d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inquiry_fields() {
        let mut d = vec![0u8; 36];
        d[0] = 0x0D;
        d[2] = 0x05;
        d[8..16].copy_from_slice(b"NETAPP  ");
        d[16..32].copy_from_slice(b"DS424IOM6       ");
        d[32..36].copy_from_slice(b"0212");
        let i = parse_inquiry(&d).unwrap();
        assert_eq!((i.device_type, i.vendor.as_str(), i.product.as_str(), i.revision.as_str()), (0x0D, "NETAPP", "DS424IOM6", "0212"));
    }

    #[test]
    fn log_temp() {
        let d = [0x0D, 0, 0, 12, 0, 0, 3, 2, 0, 38, 0, 1, 3, 2, 0, 60];
        assert_eq!(parse_log_temperature(&d), Some(38));
    }

    #[test]
    fn device_id() {
        let d = [0, 0x83, 0, 12, 0x01, 0x03, 0, 8, 0x50, 1, 2, 3, 4, 5, 6, 7];
        let v = parse_vpd_device_id(&d);
        assert_eq!(v[0].kind, "NAA");
        assert_eq!(v[0].value, "5001020304050607");
    }
}
