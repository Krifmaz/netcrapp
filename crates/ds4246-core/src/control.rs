//! Phase 2: SES control. The only write this crate can do: SEND DIAGNOSTIC
//! with an Enclosure Control page (0x02) that selects Cooling elements and
//! sets nothing but RQST ON and REQUESTED SPEED CODE (1–7).

use serde::Serialize;

use crate::ses::types::ElementType as T;
use crate::ses::{config, status, ConfigPage};
use crate::sg::{receive_diag_cdb, SgDevice};

const SELECT: u8 = 0x80;
const RQST_ON: u8 = 0x20;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("speed code {0} out of range (1-7)")]
    SpeedCode(u8),
    #[error("control page rejected by validator: {0}")]
    Invalid(String),
    #[error("reading the configuration page: {0}")]
    Config(String),
    #[error(transparent)]
    Sg(#[from] crate::sg::SgError),
}

/// Builds an Enclosure Control page selecting every Cooling element
/// (or only `fan`, a 0-based index within the cooling elements).
pub fn build_fan_request(cfg: &ConfigPage, generation: u32, code: u8, fan: Option<usize>) -> Result<Vec<u8>, ControlError> {
    if !(1..=7).contains(&code) {
        return Err(ControlError::SpeedCode(code));
    }
    let mut body = generation.to_be_bytes().to_vec();
    let mut nth_fan = 0usize;
    for t in &cfg.types {
        body.extend([0u8; 4]); // overall element: not selected
        for _ in 0..t.possible_elements {
            let pick = t.element_type == T::COOLING && fan.is_none_or(|f| f == nth_fan);
            if t.element_type == T::COOLING {
                nth_fan += 1;
            }
            if pick {
                body.extend([SELECT, 0, 0, RQST_ON | code]);
            } else {
                body.extend([0u8; 4]);
            }
        }
    }
    let mut page = vec![0x02, 0x00];
    page.extend((body.len() as u16).to_be_bytes());
    page.extend(body);
    validate(cfg, &page)?;
    Ok(page)
}

/// Independent check of a control page before it is sent: header flags
/// clear, length matches the configuration, and every selected element is a
/// Cooling element carrying only RQST ON + speed code.
pub fn validate(cfg: &ConfigPage, page: &[u8]) -> Result<(), ControlError> {
    let bad = |m: &str| Err(ControlError::Invalid(m.to_string()));
    let count: usize = cfg.types.iter().map(|t| 1 + t.possible_elements as usize).sum();
    if page.len() != 8 + 4 * count {
        return bad("length does not match the configuration page");
    }
    if page[0] != 0x02 || page[1] != 0 || u16::from_be_bytes([page[2], page[3]]) as usize != page.len() - 4 {
        return bad("bad header");
    }
    let mut off = 8;
    let mut selected = 0;
    for t in &cfg.types {
        for i in 0..=t.possible_elements as usize {
            let e = &page[off..off + 4];
            off += 4;
            if e == [0, 0, 0, 0] {
                continue;
            }
            if i == 0 {
                return bad("overall element modified");
            }
            if t.element_type != T::COOLING {
                return bad("non-cooling element selected");
            }
            if e[0] != SELECT || e[1] != 0 || e[2] != 0 || e[3] & !(RQST_ON | 0x07) != 0 || e[3] & 0x07 == 0 {
                return bad("cooling element sets more than RQST ON + speed code 1-7");
            }
            selected += 1;
        }
    }
    if selected == 0 {
        return bad("nothing selected");
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct FanReading {
    pub name: String,
    pub rpm: u32,
    pub speed_code: u8,
}

/// Reads the current fan state (page 0x01 + 0x02).
pub fn read_fans(dev: &SgDevice) -> Result<(u32, ConfigPage, Vec<FanReading>), ControlError> {
    let c = dev.read_cdb(&receive_diag_cdb(0x01, 65532), 65532)?;
    let cfg = config::parse(&c).map_err(|e| ControlError::Config(e.to_string()))?;
    let s = dev.read_cdb(&receive_diag_cdb(0x02, 65532), 65532)?;
    let st = status::parse(&s, &cfg).map_err(|e| ControlError::Config(e.to_string()))?;
    let mut fans = Vec::new();
    for (ti, t) in cfg.types.iter().enumerate() {
        if t.element_type != T::COOLING {
            continue;
        }
        for e in &st.types[ti].1 {
            if let status::ElementDetail::Fan { rpm, speed_code, .. } = e.detail {
                fans.push(FanReading { name: format!("Fan {}", fans.len() + 1), rpm, speed_code });
            }
        }
    }
    Ok((cfg.generation, cfg, fans))
}

/// Sends the fan speed request. Uses the generation code from a fresh read
/// so a changed configuration makes the enclosure reject it.
pub fn set_fan_speed(dev: &SgDevice, code: u8, fan: Option<usize>) -> Result<(), ControlError> {
    let (generation, cfg, _) = read_fans(dev)?;
    let page = build_fan_request(&cfg, generation, code, fan)?;
    dev.send_ses_control(&page)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ConfigPage {
        crate::ses::config::parse(&crate::synthetic::config_page()).unwrap()
    }

    #[test]
    fn only_fans_selected() {
        let c = cfg();
        let p = build_fan_request(&c, 1, 2, None).unwrap();
        let selected: Vec<_> = p[8..].chunks(4).filter(|e| e[0] & SELECT != 0).collect();
        assert_eq!(selected.len(), 8);
        assert!(selected.iter().all(|e| *e == [0x80, 0, 0, 0x22]));
        let one = build_fan_request(&c, 1, 3, Some(2)).unwrap();
        assert_eq!(one[8..].chunks(4).filter(|e| e[0] & SELECT != 0).count(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        let c = cfg();
        assert!(build_fan_request(&c, 1, 0, None).is_err());
        assert!(build_fan_request(&c, 1, 8, None).is_err());
        // Select the first device slot instead of a fan.
        let mut p = build_fan_request(&c, 1, 1, None).unwrap();
        p[12] = SELECT;
        assert!(validate(&c, &p).is_err());
        // Ident bit on a fan.
        let mut p = build_fan_request(&c, 1, 1, None).unwrap();
        let fan_off = (8..p.len()).step_by(4).find(|&o| p[o] == SELECT).unwrap();
        p[fan_off + 1] = 0x80;
        assert!(validate(&c, &p).is_err());
        // Header flags.
        let mut p = build_fan_request(&c, 1, 1, None).unwrap();
        p[1] = 0x02;
        assert!(validate(&c, &p).is_err());
    }
}
