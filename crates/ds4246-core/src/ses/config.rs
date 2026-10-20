//! Configuration diagnostic page (0x01), SES-3 §6.1.2.

use serde::Serialize;

use super::{bad, be32, page_body, ParseError};
use crate::scsi::ascii;

#[derive(Debug, Clone, Serialize)]
pub struct Subenclosure {
    pub id: u8,
    pub relative_es_process_id: u8,
    pub num_es_processes: u8,
    pub num_type_headers: u8,
    /// Enclosure logical identifier (a WWN — sensitive, never commit).
    pub logical_id: String,
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub vendor_specific: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeHeader {
    pub element_type: u8,
    pub possible_elements: u8,
    pub subenclosure_id: u8,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigPage {
    pub generation: u32,
    pub subenclosures: Vec<Subenclosure>,
    pub types: Vec<TypeHeader>,
}

impl ConfigPage {
    /// Total individual elements (excluding overall elements).
    pub fn element_count(&self) -> usize {
        self.types.iter().map(|t| t.possible_elements as usize).sum()
    }
}

pub fn parse(d: &[u8]) -> Result<ConfigPage, ParseError> {
    let d = page_body(0x01, d)?;
    if d.len() < 8 {
        return Err(bad(0x01, "no generation code"));
    }
    let generation = be32(&d[4..8]);
    let num_sub = d[1] as usize + 1;
    let mut off = 8;
    let mut subs = Vec::with_capacity(num_sub);
    for _ in 0..num_sub {
        let h = d.get(off..off + 4).ok_or_else(|| bad(0x01, "truncated enclosure descriptor"))?;
        let len = h[3] as usize + 4;
        let e = d.get(off..off + len).ok_or_else(|| bad(0x01, "truncated enclosure descriptor body"))?;
        let field = |a: usize, b: usize| e.get(a..b.min(e.len())).unwrap_or(&[]);
        subs.push(Subenclosure {
            relative_es_process_id: (e[0] >> 4) & 0x07,
            num_es_processes: e[0] & 0x07,
            id: e[1],
            num_type_headers: e[2],
            logical_id: field(4, 12).iter().map(|b| format!("{b:02x}")).collect(),
            vendor: ascii(field(12, 20)),
            product: ascii(field(20, 36)),
            revision: ascii(field(36, 40)),
            vendor_specific: field(40, len).to_vec(),
        });
        off += len;
    }
    let n_types: usize = subs.iter().map(|s| s.num_type_headers as usize).sum();
    let mut types = Vec::with_capacity(n_types);
    let mut text_lens = Vec::with_capacity(n_types);
    for _ in 0..n_types {
        let h = d.get(off..off + 4).ok_or_else(|| bad(0x01, "truncated type descriptor header"))?;
        types.push(TypeHeader { element_type: h[0], possible_elements: h[1], subenclosure_id: h[2], text: String::new() });
        text_lens.push(h[3] as usize);
        off += 4;
    }
    for (t, len) in types.iter_mut().zip(text_lens) {
        // Missing text is tolerated: some firmware truncates it.
        t.text = ascii(d.get(off..(off + len).min(d.len())).unwrap_or(&[]));
        off += len;
    }
    Ok(ConfigPage { generation, subenclosures: subs, types })
}
