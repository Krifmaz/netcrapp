//! Additional element status diagnostic page (0x0A), SES-3 §6.1.13.
//! Only the SAS protocol-specific layout is decoded; others are kept raw.

use serde::Serialize;

use super::types::ElementType;
use super::{bad, be32, page_body, ConfigPage, ParseError};

#[derive(Debug, Clone, Serialize)]
pub struct AddlPage {
    pub generation: u32,
    pub descriptors: Vec<AddlDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AddlDescriptor {
    pub invalid: bool,
    pub eip: bool,
    pub eiioe: u8,
    pub protocol: u8,
    pub protocol_name: &'static str,
    /// Index into the individual elements (overall elements excluded).
    pub element_index: Option<usize>,
    pub sas: Option<SasInfo>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SasInfo {
    Slot { not_all_phys: bool, device_slot_number: Option<u8>, phys: Vec<Phy> },
    Expander { sas_address: String, phys: Vec<ExpanderPhy> },
    Ports { phys: Vec<PortPhy> },
}

#[derive(Debug, Clone, Serialize)]
pub struct Phy {
    pub device_type: u8,
    pub device_type_name: &'static str,
    pub initiator: Vec<&'static str>,
    pub target: Vec<&'static str>,
    pub sata_device: bool,
    pub sata_port_selector: bool,
    /// Address of what the expander phy sees (sensitive).
    pub attached_sas_address: String,
    /// The device's own SAS address (sensitive).
    pub sas_address: String,
    pub phy_id: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExpanderPhy {
    pub connector_element_index: u8,
    pub other_element_index: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortPhy {
    pub phy_id: u8,
    pub connector_element_index: u8,
    pub other_element_index: u8,
    pub sas_address: String,
}

fn protocol_name(p: u8) -> &'static str {
    match p {
        0x0 => "Fibre Channel",
        0x1 => "SPI",
        0x2 => "SSA",
        0x3 => "IEEE 1394",
        0x4 => "SRP",
        0x5 => "iSCSI",
        0x6 => "SAS",
        0x7 => "ADT",
        0x8 => "ATA/ATAPI",
        0x9 => "UAS",
        0xA => "SOP",
        0xB => "PCIe",
        _ => "other",
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Maps an ELEMENT INDEX that counts overall elements to an individual index.
fn index_from_including_overall(cfg: &ConfigPage, idx: usize) -> Option<usize> {
    let (mut pos, mut indiv) = (0usize, 0usize);
    for t in &cfg.types {
        let n = t.possible_elements as usize;
        if idx == pos {
            return None; // points at an overall element
        }
        if idx > pos && idx <= pos + n {
            return Some(indiv + idx - pos - 1);
        }
        pos += n + 1;
        indiv += n;
    }
    None
}

fn parse_sas(eltype: Option<u8>, eip: bool, p: &[u8]) -> Option<SasInfo> {
    if p.len() < 2 {
        return None;
    }
    let nphy = p[0] as usize;
    match p[1] >> 6 {
        0 => {
            let mut phys = Vec::new();
            for i in 0..nphy {
                let Some(d) = p.get(4 + i * 28..4 + (i + 1) * 28) else { break };
                let dt = (d[0] >> 4) & 0x07;
                let mut initiator = Vec::new();
                let mut target = Vec::new();
                for (bit, name) in [(3, "SSP"), (2, "STP"), (1, "SMP")] {
                    if d[2] & (1 << bit) != 0 {
                        initiator.push(name);
                    }
                    if d[3] & (1 << bit) != 0 {
                        target.push(name);
                    }
                }
                phys.push(Phy {
                    device_type: dt,
                    device_type_name: match dt {
                        0 => "no device",
                        1 => "end device",
                        2 => "expander",
                        3 => "fanout expander",
                        _ => "reserved",
                    },
                    initiator,
                    target,
                    sata_device: d[3] & 0x01 != 0,
                    sata_port_selector: d[3] & 0x80 != 0,
                    attached_sas_address: hex(&d[4..12]),
                    sas_address: hex(&d[12..20]),
                    phy_id: d[20],
                });
            }
            Some(SasInfo::Slot { not_all_phys: p[1] & 0x01 != 0, device_slot_number: (eip && p.len() > 3).then(|| p[3]), phys })
        }
        1 if eltype == Some(ElementType::SAS_EXPANDER) => {
            let sas_address = hex(p.get(4..12)?);
            let phys = (0..nphy)
                .filter_map(|i| p.get(12 + i * 2..14 + i * 2))
                .map(|d| ExpanderPhy { connector_element_index: d[0], other_element_index: d[1] })
                .collect();
            Some(SasInfo::Expander { sas_address, phys })
        }
        1 => {
            let phys = (0..nphy)
                .filter_map(|i| p.get(4 + i * 12..16 + i * 12))
                .map(|d| PortPhy {
                    phy_id: d[0],
                    connector_element_index: d[2],
                    other_element_index: d[3],
                    sas_address: hex(&d[4..12]),
                })
                .collect();
            Some(SasInfo::Ports { phys })
        }
        _ => None,
    }
}

pub fn parse(d: &[u8], cfg: &ConfigPage) -> Result<AddlPage, ParseError> {
    let d = page_body(0x0A, d)?;
    if d.len() < 8 {
        return Err(bad(0x0A, "no generation code"));
    }
    // Element type per individual index, and the sequence used when EIP=0.
    let types: Vec<u8> = cfg.types.iter().flat_map(|t| std::iter::repeat(t.element_type).take(t.possible_elements as usize)).collect();
    let mut seq = types.iter().enumerate().filter(|(_, &t)| ElementType(t).has_addl_status()).map(|(i, _)| i);

    let mut descriptors = Vec::new();
    let mut off = 8;
    while off + 2 <= d.len() {
        let len = d[off + 1] as usize + 2;
        let Some(desc) = d.get(off..off + len) else { break };
        off += len;
        let invalid = desc[0] & 0x80 != 0;
        let eip = desc[0] & 0x10 != 0;
        let protocol = desc[0] & 0x0F;
        let (eiioe, element_index, body) = if eip && desc.len() >= 4 {
            let eiioe = desc[2] & 0x03;
            let raw_idx = desc[3] as usize;
            let idx = match eiioe {
                1 | 2 => index_from_including_overall(cfg, raw_idx),
                _ => Some(raw_idx),
            };
            (eiioe, idx, &desc[4..])
        } else {
            (0, seq.next(), &desc[2..])
        };
        let eltype = element_index.and_then(|i| types.get(i).copied());
        let sas = (protocol == 6 && !invalid).then(|| parse_sas(eltype, eip, body)).flatten();
        descriptors.push(AddlDescriptor {
            invalid,
            eip,
            eiioe,
            protocol,
            protocol_name: protocol_name(protocol),
            element_index,
            sas,
            raw: desc.to_vec(),
        });
    }
    Ok(AddlPage { generation: be32(&d[4..8]), descriptors })
}
