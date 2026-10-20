//! Enclosure status diagnostic page (0x02), SES-3 §6.1.4 and §7.

use serde::Serialize;

use super::types::ElementType as T;
use super::{bad, be32, page_body, ConfigPage, ParseError};

#[derive(Debug, Clone, Serialize)]
pub struct StatusPage {
    pub invop: bool,
    pub info: bool,
    pub non_crit: bool,
    pub crit: bool,
    pub unrecov: bool,
    pub generation: u32,
    /// One entry per type header: (overall element, individual elements).
    pub types: Vec<(ElementStatus, Vec<ElementStatus>)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElementStatus {
    pub raw: [u8; 4],
    pub code: u8,
    pub code_name: &'static str,
    pub prdfail: bool,
    pub disabled: bool,
    pub swap: bool,
    pub ident: bool,
    pub fail: bool,
    /// Names of every set bit in bytes 1..3 (per the element type's layout).
    pub bits: Vec<&'static str>,
    pub detail: ElementDetail,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ElementDetail {
    None,
    Slot { slot_address: Option<u8>, fault_sensed: bool, fault_requested: bool, device_off: bool },
    Fan { rpm: u32, speed_code: u8, speed_name: &'static str, off: bool, requested_on: bool },
    Psu { off: bool, requested_on: bool, ac_fail: bool, dc_fail: bool },
    Temperature { celsius: Option<i16> },
    Voltage { volts: f32 },
    Current { amps: f32 },
    Enclosure {
        failure_indication: bool,
        warning_indication: bool,
        failure_requested: bool,
        warning_requested: bool,
        time_until_power_cycle: u8,
        requested_power_off_duration: u8,
    },
    Display { mode: u8, character: u16 },
    Alarm { muted: bool, tone_urgency: u8 },
    Connector { connector_type: u8, connector_type_name: &'static str, physical_link: u8 },
}

pub fn status_code_name(c: u8) -> &'static str {
    match c {
        0 => "Unsupported",
        1 => "OK",
        2 => "Critical",
        3 => "Noncritical",
        4 => "Unrecoverable",
        5 => "Not installed",
        6 => "Unknown",
        7 => "Not available",
        8 => "No access allowed",
        _ => "Reserved",
    }
}

pub fn fan_speed_name(code: u8) -> &'static str {
    match code {
        0 => "stopped",
        1 => "lowest",
        2 => "second lowest",
        3 => "third lowest",
        4 => "intermediate",
        5 => "third highest",
        6 => "second highest",
        _ => "highest",
    }
}

fn connector_type_name(t: u8) -> &'static str {
    match t {
        0x00 => "unknown",
        0x01 => "SAS 4x (SFF-8470)",
        0x02 => "Mini SAS 4x (SFF-8088)",
        0x03 => "QSFP+ (SFF-8436)",
        0x04 => "Mini SAS 4x active (SFF-8088)",
        0x05 => "Mini SAS HD 4x (SFF-8644)",
        0x06 => "Mini SAS HD 8x",
        0x07 => "Mini SAS HD 16x",
        0x0F => "vendor specific external",
        0x10 => "SAS 4i (SFF-8484)",
        0x11 => "Mini SAS 4i (SFF-8087)",
        0x12 => "Mini SAS HD 4i (SFF-8643)",
        0x20 => "SAS drive backplane receptacle (SFF-8482)",
        0x21 => "SATA host plug",
        0x22 => "SAS drive plug (SFF-8482)",
        0x23 => "SATA device plug",
        0x24 => "Micro SAS receptacle",
        0x2F => "SAS virtual connector",
        0x3F => "vendor specific internal",
        _ => "other",
    }
}

type Bits = [Option<&'static str>; 8]; // index 0 = bit 7

const NONE: Bits = [None; 8];
const IDENT_FAIL: Bits = [Some("IDENT"), Some("FAIL"), None, None, None, None, None, None];
const IDENT_DNR: Bits = [Some("IDENT"), Some("DO NOT REMOVE"), None, None, None, None, None, None];
const SLOT_B2: Bits = [
    Some("APP CLIENT BYPASSED A"),
    Some("DO NOT REMOVE"),
    Some("ENCLOSURE BYPASSED A"),
    Some("ENCLOSURE BYPASSED B"),
    Some("READY TO INSERT"),
    Some("RMV"),
    Some("IDENT"),
    Some("REPORT"),
];
const SLOT_B3: Bits = [
    Some("APP CLIENT BYPASSED B"),
    Some("FAULT SENSED"),
    Some("FAULT REQSTD"),
    Some("DEVICE OFF"),
    Some("BYPASSED A"),
    Some("BYPASSED B"),
    Some("DEVICE BYPASSED A"),
    Some("DEVICE BYPASSED B"),
];
const ARRAY_B1: Bits = [
    Some("OK"),
    Some("RSVD DEVICE"),
    Some("HOT SPARE"),
    Some("CONS CHK"),
    Some("IN CRIT ARRAY"),
    Some("IN FAILED ARRAY"),
    Some("REBUILD/REMAP"),
    Some("R/R ABORT"),
];
const REPORT: Bits = [None, None, None, None, None, None, None, Some("REPORT")];

/// Bit names for bytes 1, 2 and 3 of a status element.
fn layout(t: u8) -> [Bits; 3] {
    match t {
        T::DEVICE_SLOT => [NONE, SLOT_B2, SLOT_B3],
        T::ARRAY_DEVICE_SLOT => [ARRAY_B1, SLOT_B2, SLOT_B3],
        T::POWER_SUPPLY => [
            IDENT_DNR,
            [None, None, None, None, Some("DC OVER-VOLTAGE"), Some("DC UNDER-VOLTAGE"), Some("DC OVER-CURRENT"), None],
            [Some("HOT SWAP"), Some("FAIL"), Some("RQSTED ON"), Some("OFF"), Some("OVERTMP FAIL"), Some("TEMP WARN"), Some("AC FAIL"), Some("DC FAIL")],
        ],
        T::COOLING => [IDENT_DNR, NONE, [Some("HOT SWAP"), Some("FAIL"), Some("RQSTED ON"), Some("OFF"), None, None, None, None]],
        T::TEMPERATURE => [
            IDENT_FAIL,
            NONE,
            [None, None, None, None, Some("OT FAILURE"), Some("OT WARNING"), Some("UT FAILURE"), Some("UT WARNING")],
        ],
        T::DOOR => [IDENT_FAIL, NONE, [None, None, None, None, None, None, Some("OPEN"), Some("UNLOCKED")]],
        T::AUDIBLE_ALARM => [
            IDENT_FAIL,
            NONE,
            [Some("RQST MUTE"), Some("MUTED"), None, Some("REMIND"), Some("TONE INFO"), Some("TONE NON-CRIT"), Some("TONE CRIT"), Some("TONE UNRECOV")],
        ],
        T::ESC_ELECTRONICS => [IDENT_FAIL, REPORT, [Some("HOT SWAP"), None, None, None, None, None, None, None]],
        T::SCC_ELECTRONICS => [IDENT_FAIL, REPORT, NONE],
        T::UPS => [
            NONE,
            [Some("AC LO"), Some("AC HI"), Some("AC QUAL"), Some("AC FAIL"), Some("DC FAIL"), Some("UPS FAIL"), Some("WARN"), Some("INTF FAIL")],
            [Some("IDENT"), Some("FAIL"), None, None, None, None, Some("BATT FAIL"), Some("BPF")],
        ],
        T::ENCLOSURE => [
            [Some("IDENT"), None, None, None, None, None, None, None],
            [None, None, None, None, None, None, Some("FAILURE INDICATION"), Some("WARNING INDICATION")],
            [None, None, None, None, None, None, Some("FAILURE REQUESTED"), Some("WARNING REQUESTED")],
        ],
        T::SCSI_PORT_XCVR => [IDENT_FAIL, REPORT, [None, None, None, Some("DISABLED"), None, None, Some("LOL"), Some("XMIT FAIL")]],
        T::LANGUAGE => [[Some("IDENT"), None, None, None, None, None, None, None], NONE, NONE],
        T::COMM_PORT => [IDENT_FAIL, NONE, [None, None, None, None, None, None, None, Some("DISABLED")]],
        T::VOLTAGE => [
            [Some("IDENT"), Some("FAIL"), None, None, Some("WARN OVER"), Some("WARN UNDER"), Some("CRIT OVER"), Some("CRIT UNDER")],
            NONE,
            NONE,
        ],
        T::CURRENT => [[Some("IDENT"), Some("FAIL"), None, None, Some("WARN OVER"), None, Some("CRIT OVER"), None], NONE, NONE],
        T::SCSI_TARGET_PORT | T::SCSI_INITIATOR_PORT => [IDENT_FAIL, REPORT, [None, None, None, None, None, None, None, Some("ENABLED")]],
        T::DISPLAY | T::KEYPAD | T::NV_CACHE | T::SIMPLE_SUBENCLOSURE | T::SAS_EXPANDER => [IDENT_FAIL, NONE, NONE],
        T::SAS_CONNECTOR => [
            [Some("IDENT"), None, None, None, None, None, None, None],
            NONE,
            [Some("MATED"), Some("FAIL"), Some("OVERCURRENT"), None, None, None, None, None],
        ],
        _ => [NONE, NONE, NONE],
    }
}

fn bit(b: u8, n: u8) -> bool {
    b & (1 << n) != 0
}

pub fn parse_element(t: u8, raw: [u8; 4]) -> ElementStatus {
    let [b0, b1, b2, b3] = raw;
    let lay = layout(t);
    let mut bits = Vec::new();
    for (i, names) in lay.iter().enumerate() {
        let byte = raw[i + 1];
        for (j, name) in names.iter().enumerate() {
            if let Some(name) = name {
                if bit(byte, 7 - j as u8) {
                    bits.push(*name);
                }
            }
        }
    }
    let has = |n: &str| bits.contains(&n);
    let detail = match t {
        T::DEVICE_SLOT | T::ARRAY_DEVICE_SLOT => ElementDetail::Slot {
            slot_address: (t == T::DEVICE_SLOT).then_some(b1),
            fault_sensed: bit(b3, 6),
            fault_requested: bit(b3, 5),
            device_off: bit(b3, 4),
        },
        T::COOLING => {
            let code = b3 & 0x07;
            ElementDetail::Fan {
                rpm: ((((b1 & 0x07) as u32) << 8) | b2 as u32) * 10,
                speed_code: code,
                speed_name: fan_speed_name(code),
                off: bit(b3, 4),
                requested_on: bit(b3, 5),
            }
        }
        T::POWER_SUPPLY => ElementDetail::Psu { off: bit(b3, 4), requested_on: bit(b3, 5), ac_fail: bit(b3, 1), dc_fail: bit(b3, 0) },
        T::TEMPERATURE => ElementDetail::Temperature { celsius: (b2 != 0).then(|| b2 as i16 - 20) },
        T::VOLTAGE => ElementDetail::Voltage { volts: i16::from_be_bytes([b2, b3]) as f32 / 100.0 },
        T::CURRENT => ElementDetail::Current { amps: i16::from_be_bytes([b2, b3]) as f32 / 100.0 },
        T::ENCLOSURE => ElementDetail::Enclosure {
            failure_indication: bit(b2, 1),
            warning_indication: bit(b2, 0),
            failure_requested: bit(b3, 1),
            warning_requested: bit(b3, 0),
            time_until_power_cycle: b2 >> 2,
            requested_power_off_duration: b3 >> 2,
        },
        T::DISPLAY => ElementDetail::Display { mode: b1 & 0x03, character: u16::from_be_bytes([b2, b3]) },
        T::AUDIBLE_ALARM => ElementDetail::Alarm { muted: bit(b3, 6), tone_urgency: b3 & 0x0F },
        T::SAS_CONNECTOR => ElementDetail::Connector {
            connector_type: b1 & 0x7F,
            connector_type_name: connector_type_name(b1 & 0x7F),
            physical_link: b2,
        },
        _ => ElementDetail::None,
    };
    ElementStatus {
        raw,
        code: b0 & 0x0F,
        code_name: status_code_name(b0 & 0x0F),
        prdfail: bit(b0, 7),
        disabled: bit(b0, 6),
        swap: bit(b0, 5),
        ident: has("IDENT"),
        fail: has("FAIL") || has("FAULT SENSED"),
        bits,
        detail,
    }
}

pub fn parse(d: &[u8], cfg: &ConfigPage) -> Result<StatusPage, ParseError> {
    let d = page_body(0x02, d)?;
    if d.len() < 8 {
        return Err(bad(0x02, "no generation code"));
    }
    let mut off = 8;
    let mut next = |t: u8| -> Result<ElementStatus, ParseError> {
        let e = d.get(off..off + 4).ok_or_else(|| bad(0x02, "fewer elements than the configuration page lists"))?;
        off += 4;
        Ok(parse_element(t, [e[0], e[1], e[2], e[3]]))
    };
    let mut types = Vec::with_capacity(cfg.types.len());
    for th in &cfg.types {
        let overall = next(th.element_type)?;
        let elems = (0..th.possible_elements).map(|_| next(th.element_type)).collect::<Result<_, _>>()?;
        types.push((overall, elems));
    }
    Ok(StatusPage {
        invop: bit(d[1], 4),
        info: bit(d[1], 3),
        non_crit: bit(d[1], 2),
        crit: bit(d[1], 1),
        unrecov: bit(d[1], 0),
        generation: be32(&d[4..8]),
        types,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fan() {
        // OK, 0x2D0 * 10 = 7200 rpm, speed code 7, RQSTED ON
        let e = parse_element(T::COOLING, [0x01, 0x02, 0xD0, 0x27]);
        match e.detail {
            ElementDetail::Fan { rpm, speed_code, .. } => assert_eq!((rpm, speed_code), (7200, 7)),
            _ => panic!(),
        }
        assert_eq!(e.bits, vec!["RQSTED ON"]);
    }

    #[test]
    fn enclosure_led() {
        let e = parse_element(T::ENCLOSURE, [0x01, 0x00, 0x02, 0x00]);
        assert!(e.bits.contains(&"FAILURE INDICATION"));
    }

    #[test]
    fn temp_and_voltage() {
        let e = parse_element(T::TEMPERATURE, [0x01, 0, 20 + 31, 0]);
        assert!(matches!(e.detail, ElementDetail::Temperature { celsius: Some(31) }));
        let v = parse_element(T::VOLTAGE, [0x03, 0x08, 0x04, 0xB0]);
        assert!(matches!(v.detail, ElementDetail::Voltage { volts } if (volts - 12.0).abs() < 0.001));
        assert_eq!(v.code_name, "Noncritical");
        assert_eq!(v.bits, vec!["WARN OVER"]);
    }
}
