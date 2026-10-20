//! Hex dump helpers for the `.txt` dumps and the Raw pages tab.

use std::fmt::Write;

pub fn hex_line(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Classic `offset  hex  |ascii|` dump, 16 bytes per row.
pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", row * 16);
        for i in 0..16 {
            match chunk.get(i) {
                Some(b) => {
                    let _ = write!(out, "{b:02x} ");
                }
                None => out.push_str("   "),
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        out.extend(chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }));
        out.push_str("|\n");
    }
    out
}

/// Parses a dump produced by [`hexdump`] back into bytes.
pub fn parse_hexdump(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.get(10..) else { continue };
        let hex = rest.split('|').next().unwrap_or("");
        out.extend(hex.split_whitespace().filter_map(|t| u8::from_str_radix(t, 16).ok()));
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0..=255u8).chain(0..7).collect();
        assert_eq!(super::parse_hexdump(&super::hexdump(&data)), data);
    }
}
