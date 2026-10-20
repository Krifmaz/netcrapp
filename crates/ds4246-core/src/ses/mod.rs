//! SES-3 diagnostic page parsers. All parsers work on raw byte slices so they
//! can run against live reads or saved dumps.

pub mod addl;
pub mod config;
pub mod descriptor;
pub mod status;
pub mod types;

pub use addl::{AddlDescriptor, AddlPage, Phy};
pub use config::{ConfigPage, Subenclosure, TypeHeader};
pub use descriptor::DescriptorPage;
pub use status::{ElementDetail, ElementStatus, StatusPage};
pub use types::{element_type_name, page_name, ElementType};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("page {page:#04x}: {msg}")]
    Bad { page: u8, msg: String },
}

pub(crate) fn bad(page: u8, msg: impl Into<String>) -> ParseError {
    ParseError::Bad { page, msg: msg.into() }
}

/// Validates the 4-byte page header and returns the page body bounded by the
/// PAGE LENGTH field.
pub(crate) fn page_body(page: u8, d: &[u8]) -> Result<&[u8], ParseError> {
    if d.len() < 4 {
        return Err(bad(page, "shorter than header"));
    }
    if d[0] != page {
        return Err(bad(page, format!("page code mismatch: got {:#04x}", d[0])));
    }
    let len = u16::from_be_bytes([d[2], d[3]]) as usize;
    if d.len() < 4 + len {
        return Err(bad(page, format!("truncated: header says {} bytes, have {}", 4 + len, d.len())));
    }
    Ok(&d[..4 + len])
}

/// Page 0x00 / 0x0D: list of supported page codes.
pub fn parse_supported(page: u8, d: &[u8]) -> Result<Vec<u8>, ParseError> {
    Ok(page_body(page, d)?[4..].to_vec())
}

pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
