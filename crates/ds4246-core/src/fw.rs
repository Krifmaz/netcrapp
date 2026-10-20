//! Phase 3: reading IOM buffers with READ BUFFER (modes 02h/03h only) and a
//! first-pass analysis of the image. Nothing here writes to the device.
//! Images are NetApp firmware: they live in ./dumps and are never committed.

use std::fmt::Write;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::sg::{read_buffer_cdb, SgDevice, SgError, READ_BUFFER_DATA, READ_BUFFER_DESCRIPTOR};

#[derive(Debug, Clone, Serialize)]
pub struct BufferInfo {
    pub id: u8,
    /// Offsets must be multiples of 2^offset_boundary (0xFF: offset 0 only).
    pub offset_boundary: u8,
    pub capacity: u32,
}

/// Mode 03h for every buffer ID. Returns the IDs that report a capacity.
pub fn probe(dev: &SgDevice) -> Vec<BufferInfo> {
    (0..=255u8)
        .filter_map(|id| {
            let d = dev.read_cdb(&read_buffer_cdb(READ_BUFFER_DESCRIPTOR, id, 0, 4), 4).ok()?;
            (d.len() >= 4).then(|| BufferInfo { id, offset_boundary: d[0], capacity: u32::from_be_bytes([0, d[1], d[2], d[3]]) })
        })
        .filter(|b| b.capacity > 0)
        .collect()
}

/// True if every probed ID reports the same thing (device ignores BUFFER ID).
pub fn ids_look_ignored(bufs: &[BufferInfo]) -> bool {
    bufs.len() > 8 && bufs.iter().all(|b| b.capacity == bufs[0].capacity && b.offset_boundary == bufs[0].offset_boundary)
}

/// Reads up to `max` bytes of buffer `info.id` in aligned chunks (mode 02h).
/// Returns what was read plus the error that stopped it early, if any.
pub fn read(dev: &SgDevice, info: &BufferInfo, max: u32, mut progress: impl FnMut(u32, u32)) -> (Vec<u8>, Option<SgError>) {
    let total = info.capacity.min(max).min(0xFF_FFFF);
    let mut out = Vec::with_capacity(total as usize);
    if info.offset_boundary == 0xFF {
        return match dev.read_cdb(&read_buffer_cdb(READ_BUFFER_DATA, info.id, 0, total), total as usize) {
            Ok(d) => (d, None),
            Err(e) => (out, Some(e)),
        };
    }
    let align = 1u32 << info.offset_boundary.min(24);
    let chunk = 65536u32.div_ceil(align) * align;
    let mut off = 0u32;
    while off < total {
        let len = chunk.min(total - off);
        match dev.read_cdb(&read_buffer_cdb(READ_BUFFER_DATA, info.id, off, len), len as usize) {
            Ok(d) if d.is_empty() => break,
            Ok(d) => {
                off += d.len() as u32;
                let short = (d.len() as u32) < len;
                out.extend(d);
                progress(off, total);
                if short {
                    break;
                }
            }
            Err(e) => return (out, Some(e)),
        }
        // Be gentle with the IOM's management CPU while drives are in use.
        std::thread::sleep(Duration::from_millis(5));
    }
    (out, None)
}

pub fn sha256_hex(d: &[u8]) -> String {
    Sha256::digest(d).iter().map(|b| format!("{b:02x}")).collect()
}

fn entropy(block: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let n = block.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

const MAGICS: &[(&str, &[u8])] = &[
    ("ELF", b"\x7fELF"),
    ("gzip", b"\x1f\x8b\x08"),
    ("uImage", b"\x27\x05\x19\x56"),
    ("xz", b"\xfd7zXZ\x00"),
    ("LZMA", b"\x5d\x00\x00\x80\x00"),
    ("bzip2", b"BZh9"),
    ("zip", b"PK\x03\x04"),
    ("FDT", b"\xd0\x0d\xfe\xed"),
    ("SquashFS", b"hsqs"),
    ("cramfs", b"\x45\x3d\xcd\x28"),
];

const KEYWORDS: &[&str] = &["0172", "0171", "netapp", "iom", "version", "pmc", "sierra", "lsi", "copyright", "build", "ses", "ds42", "expander", "flash", "boot"];

/// Plain-text first-pass analysis: hashes, padding, entropy map, known
/// magics and interesting strings.
pub fn analyze(d: &[u8]) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "size     {} bytes ({:#x})", d.len(), d.len());
    let _ = writeln!(o, "sha256   {}", sha256_hex(d));
    if d.is_empty() {
        return o;
    }
    let lead_ff = d.iter().take_while(|&&b| b == 0xFF).count();
    let lead_00 = d.iter().take_while(|&&b| b == 0x00).count();
    let trail = d.iter().rev().take_while(|&&b| b == 0xFF || b == 0x00).count();
    let _ = writeln!(o, "padding  leading 0xFF {lead_ff}, leading 0x00 {lead_00}, trailing 00/FF {trail}");
    let _ = writeln!(o, "first 32 {}", crate::hexdump::hex_line(&d[..32.min(d.len())]));

    let _ = writeln!(o, "\nentropy per 4 KiB block (. <1  - <4  = <6  + <7.5  # >=7.5 bits/byte):");
    let mut line = String::new();
    for (i, b) in d.chunks(4096).enumerate() {
        if i > 0 && i % 64 == 0 {
            let _ = writeln!(o, "  {:#08x} {line}", (i - 64) * 4096);
            line.clear();
        }
        let e = entropy(b);
        line.push(match e {
            e if e < 1.0 => '.',
            e if e < 4.0 => '-',
            e if e < 6.0 => '=',
            e if e < 7.5 => '+',
            _ => '#',
        });
    }
    if !line.is_empty() {
        let start = (d.len().div_ceil(4096) - line.len()) * 4096;
        let _ = writeln!(o, "  {start:#08x} {line}");
    }

    let _ = writeln!(o, "\nknown signatures:");
    let mut any = false;
    for (name, sig) in MAGICS {
        let hits: Vec<usize> = d.windows(sig.len()).enumerate().filter(|(_, w)| w == sig).map(|(i, _)| i).take(8).collect();
        if !hits.is_empty() {
            any = true;
            let _ = writeln!(o, "  {name:<9} at {}", hits.iter().map(|h| format!("{h:#x}")).collect::<Vec<_>>().join(", "));
        }
    }
    if !any {
        o.push_str("  none\n");
    }

    let mut strings = Vec::new();
    let mut cur = Vec::new();
    for (i, &b) in d.iter().enumerate() {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= 6 {
                strings.push((i - cur.len(), String::from_utf8_lossy(&cur).to_string()));
            }
            cur.clear();
        }
    }
    if cur.len() >= 6 {
        strings.push((d.len() - cur.len(), String::from_utf8_lossy(&cur).to_string()));
    }
    let _ = writeln!(o, "\nprintable strings (>= 6 chars): {}", strings.len());
    let interesting: Vec<_> = strings.iter().filter(|(_, s)| {
        let l = s.to_ascii_lowercase();
        KEYWORDS.iter().any(|k| l.contains(k))
    }).take(80).collect();
    let _ = writeln!(o, "strings with version/vendor keywords (first {}):", interesting.len());
    for (off, s) in interesting {
        let s: String = s.chars().take(100).collect();
        let _ = writeln!(o, "  {off:#08x}  {s}");
    }
    o
}

#[cfg(test)]
mod tests {
    #[test]
    fn analyze_finds_things() {
        let mut d = vec![0xFFu8; 8192];
        d[100..104].copy_from_slice(b"\x7fELF");
        d[200..230].copy_from_slice(b"IOM6 firmware version 0172 x\0\0");
        let r = super::analyze(&d);
        assert!(r.contains("ELF"));
        assert!(r.contains("version 0172"));
        assert!(r.contains("leading 0xFF 100"));
    }
}
