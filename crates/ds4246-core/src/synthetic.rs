//! SYNTHETIC SES pages shaped like a DS4246 with a few faults injected.
//! Invented data (fake SAS addresses, no real serials) for tests and `--demo`.
//! It is NOT a capture from real hardware.

use chrono::Utc;

use crate::collect::{EnclosureRead, RawPage};
use crate::discover::DiskInfo;
use crate::scsi::IdentityRaw;
use crate::ses::page_name;
use crate::ses::types::{is_vendor_page, ElementType as T};

/// (type, count, type text)
const LAYOUT: &[(u8, u8, &str)] = &[
    (T::ARRAY_DEVICE_SLOT, 24, "Disk Drives"),
    (T::POWER_SUPPLY, 4, "Power Supplies"),
    (T::COOLING, 8, "Cooling Fans"),
    (T::TEMPERATURE, 6, "Temperature Sensors"),
    (T::ESC_ELECTRONICS, 2, "ESCE IOMs"),
    (T::ENCLOSURE, 1, "Enclosure"),
    (T::DISPLAY, 1, "Shelf ID Display"),
    (T::VOLTAGE, 4, "Voltage Sensors"),
    (T::CURRENT, 2, "Current Sensors"),
    (T::SAS_EXPANDER, 1, "SAS Expander"),
    (T::SAS_CONNECTOR, 4, "SAS Connectors"),
];

fn page(code: u8, body: Vec<u8>) -> Vec<u8> {
    let mut p = vec![code, 0];
    p.extend_from_slice(&(body.len() as u16).to_be_bytes());
    p.extend(body);
    p
}

fn pad(s: &str, n: usize) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.resize(n, b' ');
    v
}

pub fn config_page() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 1]; // generation 1
    b.extend([0x11, 0x00, LAYOUT.len() as u8, 36]);
    b.extend([0x50, 0, 0, 0, 0, 0, 0, 0x01]); // fake logical id
    b.extend(pad("SYNTH", 8));
    b.extend(pad("DS424IOM6", 16));
    b.extend(pad("0000", 4));
    for (t, n, text) in LAYOUT {
        b.extend([*t, *n, 0, text.len() as u8]);
    }
    for (_, _, text) in LAYOUT {
        b.extend(text.as_bytes());
    }
    page(0x01, b)
}

fn element(t: u8, i: usize) -> [u8; 4] {
    match t {
        T::ARRAY_DEVICE_SLOT => match i {
            5 => [0x05, 0, 0, 0],          // empty bay
            9 => [0x02, 0x80, 0, 0x40],    // fault sensed
            13 => [0x01, 0x80, 0x02, 0x00], // ident
            _ => [0x01, 0x80, 0, 0],
        },
        T::POWER_SUPPLY => match i {
            2 => [0x02, 0, 0, 0x42],   // critical, FAIL + AC FAIL
            3 => [0x05, 0, 0, 0],      // not installed
            _ => [0x01, 0, 0, 0x20],
        },
        T::COOLING => {
            let rpm10: u16 = 1420 + i as u16 * 3;
            [0x01, (rpm10 >> 8) as u8 & 7, rpm10 as u8, 0x27]
        }
        T::TEMPERATURE => [0x01, 0, 20 + 24 + i as u8 * 2, 0],
        T::ESC_ELECTRONICS => match i {
            0 => [0x01, 0, 0x01, 0x80], // this IOM, REPORT
            _ => [0x05, 0, 0, 0],       // partner not installed
        },
        T::ENCLOSURE => [0x01, 0, 0x02, 0x00], // FAILURE INDICATION
        T::DISPLAY => [0x01, 0x01, b'0', b'0'],
        T::VOLTAGE => {
            let v: i16 = [500, 1200, 330, 120][i % 4];
            let [h, l] = v.to_be_bytes();
            [0x01, 0, h, l]
        }
        T::CURRENT => [0x01, 0, 0x02, 0x58],
        T::SAS_CONNECTOR => [0x01, 0x02, 0, 0x80],
        _ => [0x01, 0, 0, 0],
    }
}

pub fn status_page() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 1];
    for (t, n, _) in LAYOUT {
        b.extend([0, 0, 0, 0]);
        for i in 0..*n as usize {
            b.extend(element(*t, i));
        }
    }
    let mut p = page(0x02, b);
    p[1] = 0x02; // CRIT
    p
}

pub fn descriptor_page() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 1];
    for (t, n, _) in LAYOUT {
        b.extend([0, 0, 0, 0]);
        for i in 0..*n as usize {
            let s = match *t {
                T::POWER_SUPPLY => format!("Power Supply {}", i + 1),
                T::COOLING => format!("Fan {}", i + 1),
                T::TEMPERATURE => format!("Temp Sensor {}", i + 1),
                _ => String::new(),
            };
            b.extend([0, 0]);
            b.extend((s.len() as u16).to_be_bytes());
            b.extend(s.as_bytes());
        }
    }
    page(0x07, b)
}

pub fn addl_page() -> Vec<u8> {
    let mut b = vec![0, 0, 0, 1];
    for i in 0..24u8 {
        if i == 5 {
            continue;
        }
        let mut d = vec![0x16, 0, 0, i]; // EIP=1, SAS, EIIOE=0, element index i
        d.extend([1, 0, 0, i]); // 1 phy, type 0, slot number i
        let mut phy = vec![0x10, 0, 0, 0x08];
        phy.extend([0x50, 0, 0, 0, 0, 0, 0x10, i]); // attached (expander) — fake
        phy.extend([0x50, 0, 0, 0, 0, 0, 0x20, i]); // device — fake
        phy.extend([i, 0, 0, 0, 0, 0, 0, 0]);
        d.extend(phy);
        d[1] = (d.len() - 2) as u8;
        b.extend(d);
    }
    page(0x0A, b)
}

/// Invented disks matching the fake SAS addresses in [`addl_page`].
pub fn disks() -> Vec<DiskInfo> {
    (0..24u8)
        .filter(|&i| i != 5)
        .map(|i| DiskInfo {
            sg: format!("sg{}", i + 10),
            block: Some(format!("sd{}", (b'a' + i) as char)),
            hctl: Some(format!("0:0:{}:0", i + 1)),
            vendor: "SYNTH".into(),
            model: if i % 3 == 0 { "ST4000NM0023".into() } else { "ST8000NM0055".into() },
            display_model: if i % 3 == 0 { "ST4000NM0023".into() } else { "ST8000NM0055".into() },
            rev: "0000".into(),
            serial: None,
            size_bytes: Some(4_000_787_030_016),
            sas_address: Some(format!("50000000000020{i:02x}")),
            temperature_c: Some(30 + (i % 7) + if i == 9 { 25 } else { 0 }),
            kernel_slot: None,
        })
        .collect()
}

pub fn read() -> EnclosureRead {
    let mut pages = vec![
        (0x01, config_page()),
        (0x02, status_page()),
        (0x07, descriptor_page()),
        (0x0A, addl_page()),
        (0x05, page(0x05, vec![0; 8])),
        (0x0E, page(0x0E, vec![0, 0, 0, 1])),
        (0x10, page(0x10, (0..32).collect())),
        (0x80, page(0x80, b"SYNTHETIC VENDOR PAGE".to_vec())),
        (0x81, page(0x81, (0..64).map(|x: u8| x.wrapping_mul(37)).collect())),
    ];
    let mut codes: Vec<u8> = pages.iter().map(|p| p.0).collect();
    codes.insert(0, 0);
    codes.sort();
    pages.push((0x00, page(0x00, codes.clone())));
    pages.sort_by_key(|p| p.0);

    let mut inq = vec![0x0D, 0, 0x05, 0x02, 31, 0, 0x40, 0];
    inq.extend(pad("SYNTH", 8));
    inq.extend(pad("DS424IOM6", 16));
    inq.extend(pad("0000", 4));
    EnclosureRead {
        device: "demo0".into(),
        hctl: Some("0:0:0:0".into()),
        read_at: Utc::now(),
        full: true,
        identity: IdentityRaw { inquiry: Some(inq), vpd: vec![(0x80, Ok(vec![0x0D, 0x80, 0, 9, b'S', b'Y', b'N', b'T', b'H', b'E', b'T', b'I', b'C']))] },
        supported: codes,
        pages: pages
            .into_iter()
            .map(|(code, data)| RawPage { code, name: page_name(code), vendor: is_vendor_page(code), data: Some(data), error: None })
            .collect(),
        errors: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::report::{build, Level};
    use crate::ses::status::ElementDetail;

    #[test]
    fn synthetic_roundtrip() {
        let r = build(&super::read(), &[]);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(r.elements.len(), 57);
        assert_eq!(r.led.indicator_on, Some(true));
        assert!(r.led.reasons.iter().any(|x| x.source == "Power Supply 3" && x.level == Level::Critical));
        let bays: Vec<_> = r.of_type(&[0x17]).collect();
        assert_eq!(bays.len(), 24);
        assert_eq!(bays[7].slot_number, Some(7));
        assert!(bays[7].addl.is_some());
        assert!(bays[5].addl.is_none());
        assert!(r.of_type(&[0x07]).next().unwrap().reporting);
        assert_eq!(r.vendor_pages, vec![0x10, 0x80, 0x81]);
        let fan = r.of_type(&[0x03]).next().unwrap();
        assert!(matches!(fan.status.detail, ElementDetail::Fan { rpm: 14200, speed_code: 7, .. }));
        assert_eq!(fan.name, "Fan 1");
        assert!(r.led.hints.iter().any(|h| h.contains("speed code 6–7")));
        let with_disks = build(&super::read(), &super::disks());
        assert_eq!(with_disks.of_type(&[0x17]).filter(|e| e.disk.is_some()).count(), 23);
        let txt = {
            let mut s = String::new();
            crate::text::render_enclosure(&mut s, &r);
            s
        };
        assert!(txt.contains("FAULT LED"));
    }

    #[test]
    fn dump_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ds4246-test-{}", std::process::id()));
        let read = super::read();
        let out = crate::collect::save_dump(&dir, &read, "summary").unwrap();
        let back = crate::collect::load_dump(&out).unwrap();
        assert_eq!(back.supported, read.supported);
        assert_eq!(back.page(0x02), read.page(0x02));
        assert_eq!(back.page(0x81), read.page(0x81));
        assert_eq!(build(&back, &[]).elements.len(), 57);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
