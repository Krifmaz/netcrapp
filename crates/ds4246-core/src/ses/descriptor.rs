//! Element descriptor diagnostic page (0x07), SES-3 §6.1.10.

use serde::Serialize;

use super::{bad, be32, page_body, ConfigPage, ParseError};
use crate::scsi::ascii;

#[derive(Debug, Clone, Serialize)]
pub struct DescriptorPage {
    pub generation: u32,
    /// One entry per type header: (overall descriptor, per-element descriptors).
    pub types: Vec<(String, Vec<String>)>,
}

pub fn parse(d: &[u8], cfg: &ConfigPage) -> Result<DescriptorPage, ParseError> {
    let d = page_body(0x07, d)?;
    if d.len() < 8 {
        return Err(bad(0x07, "no generation code"));
    }
    let mut off = 8;
    let mut next = || -> Option<String> {
        let h = d.get(off..off + 4)?;
        let len = u16::from_be_bytes([h[2], h[3]]) as usize;
        let s = ascii(d.get(off + 4..(off + 4 + len).min(d.len()))?);
        off += 4 + len;
        Some(s)
    };
    let mut types = Vec::with_capacity(cfg.types.len());
    for t in &cfg.types {
        let overall = next().unwrap_or_default();
        let elems = (0..t.possible_elements).map(|_| next().unwrap_or_default()).collect();
        types.push((overall, elems));
    }
    Ok(DescriptorPage { generation: be32(&d[4..8]), types })
}
