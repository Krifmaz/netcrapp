//! Turns raw pages into named elements, flags, and the fault-LED explanation.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::collect::EnclosureRead;
use crate::discover::{norm_sas, DiskInfo};
use crate::scsi::{identity_from_raw, Identity};
use crate::ses::addl::{self, AddlDescriptor, SasInfo};
use crate::ses::status::{ElementDetail, ElementStatus};
use crate::ses::types::{element_short_name, element_type_name, ElementType, ElementType as T};
use crate::ses::{config, descriptor, status, ConfigPage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Level {
    Info,
    Ident,
    Noncritical,
    Fail,
    Critical,
    Unrecoverable,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "Info",
            Level::Ident => "Ident",
            Level::Noncritical => "Noncrit",
            Level::Fail => "Fail",
            Level::Critical => "Crit",
            Level::Unrecoverable => "Unrecov",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Flag {
    pub level: Level,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Element {
    /// Individual element index (overall elements excluded), as SES counts them.
    pub index: usize,
    pub type_code: u8,
    pub type_name: &'static str,
    /// Position within its type header (0-based).
    pub type_index: usize,
    pub subenclosure: u8,
    pub descriptor: String,
    pub name: String,
    pub status: ElementStatus,
    pub addl: Option<AddlDescriptor>,
    pub slot_number: Option<u8>,
    pub disk: Option<DiskInfo>,
    pub flags: Vec<Flag>,
    /// For IOMs: true if this is the controller answering on this sg device.
    pub reporting: bool,
}

impl Element {
    pub fn worst(&self) -> Option<Level> {
        self.flags.iter().map(|f| f.level).max()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Group {
    pub type_code: u8,
    pub type_name: &'static str,
    pub text: String,
    pub subenclosure: u8,
    pub overall: Option<ElementStatus>,
    pub overall_descriptor: String,
    pub elements: Vec<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reason {
    pub level: Level,
    pub source: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedReport {
    /// What the Enclosure element says about its failure/warning indicator.
    pub indicator_on: Option<bool>,
    pub headline: String,
    pub reasons: Vec<Reason>,
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnclosureReport {
    pub device: String,
    pub hctl: Option<String>,
    pub read_at: DateTime<Utc>,
    pub identity: Identity,
    pub supported: Vec<u8>,
    pub vendor_pages: Vec<u8>,
    pub config: Option<ConfigPage>,
    pub page_flags: Vec<&'static str>,
    pub groups: Vec<Group>,
    pub elements: Vec<Element>,
    pub errors: Vec<String>,
    pub led: LedReport,
}

impl EnclosureReport {
    pub fn logical_id(&self) -> Option<&str> {
        self.config.as_ref()?.subenclosures.first().map(|s| s.logical_id.as_str())
    }

    pub fn firmware(&self) -> Option<&str> {
        self.identity.inquiry.as_ref().map(|i| i.revision.as_str())
    }

    pub fn of_type<'a>(&'a self, codes: &'a [u8]) -> impl Iterator<Item = &'a Element> + 'a {
        self.elements.iter().filter(move |e| codes.contains(&e.type_code))
    }
}

fn default_name(t: u8, i: usize, count: usize) -> String {
    match t {
        T::DEVICE_SLOT | T::ARRAY_DEVICE_SLOT => format!("Bay {i}"),
        T::ESC_ELECTRONICS if count == 2 => format!("IOM {}", if i == 0 { 'A' } else { 'B' }),
        T::ENCLOSURE if count == 1 => "Enclosure".into(),
        T::DISPLAY if count == 1 => "Display".into(),
        _ => format!("{} {}", element_short_name(t), i + 1),
    }
}

fn element_flags(t: u8, s: &ElementStatus) -> Vec<Flag> {
    let mut f = Vec::new();
    let mut add = |level, text: &str| f.push(Flag { level, text: text.to_string() });
    match s.code {
        2 => add(Level::Critical, "status is Critical"),
        3 => add(Level::Noncritical, "status is Noncritical"),
        4 => add(Level::Unrecoverable, "status is Unrecoverable"),
        5 if matches!(t, T::POWER_SUPPLY | T::COOLING | T::ESC_ELECTRONICS) => add(Level::Info, "not installed"),
        6 => add(Level::Info, "status Unknown"),
        _ => {}
    }
    if s.prdfail {
        add(Level::Noncritical, "predicted failure (PRDFAIL)");
    }
    for &b in &s.bits {
        match b {
            "FAIL" => add(Level::Fail, "FAIL bit set"),
            "IDENT" => add(Level::Ident, "identify (locate) indicator on"),
            "AC FAIL" => add(Level::Fail, "AC FAIL: no AC input on this PSU"),
            "DC FAIL" => add(Level::Fail, "DC FAIL: PSU output failed"),
            "OVERTMP FAIL" => add(Level::Fail, "PSU over-temperature failure"),
            "TEMP WARN" => add(Level::Noncritical, "PSU over-temperature warning"),
            "DC OVER-VOLTAGE" | "DC UNDER-VOLTAGE" | "DC OVER-CURRENT" => add(Level::Fail, b),
            "OFF" => add(Level::Noncritical, "turned off"),
            "OT FAILURE" => add(Level::Critical, "over-temperature failure"),
            "UT FAILURE" => add(Level::Critical, "under-temperature failure"),
            "OT WARNING" => add(Level::Noncritical, "over-temperature warning"),
            "UT WARNING" => add(Level::Noncritical, "under-temperature warning"),
            "CRIT OVER" | "CRIT UNDER" => add(Level::Critical, &format!("voltage/current {b}")),
            "WARN OVER" | "WARN UNDER" => add(Level::Noncritical, &format!("voltage/current {b}")),
            "FAULT SENSED" => add(Level::Fail, "drive fault sensed by the enclosure"),
            "FAULT REQSTD" => add(Level::Fail, "drive fault LED requested by a host"),
            "FAILURE INDICATION" => add(Level::Critical, "enclosure FAILURE indicator is ON (front amber LED)"),
            "WARNING INDICATION" => add(Level::Noncritical, "enclosure WARNING indicator is ON"),
            "FAILURE REQUESTED" => add(Level::Fail, "a host REQUESTED the failure indicator (latched until cleared via SES control)"),
            "WARNING REQUESTED" => add(Level::Noncritical, "a host REQUESTED the warning indicator"),
            "LOL" => add(Level::Noncritical, "loss of link"),
            "XMIT FAIL" => add(Level::Fail, "transmitter failure"),
            "UPS FAIL" | "BATT FAIL" | "INTF FAIL" => add(Level::Fail, b),
            _ => {}
        }
    }
    f
}

fn slot_disk<'a>(addl: Option<&AddlDescriptor>, slot: Option<u8>, hctl: Option<&str>, disks: &'a [DiskInfo]) -> Option<&'a DiskInfo> {
    if let Some(SasInfo::Slot { phys, .. }) = addl.and_then(|a| a.sas.as_ref()) {
        let addrs: Vec<String> = phys.iter().flat_map(|p| [p.sas_address.clone(), p.attached_sas_address.clone()]).filter(|a| a.chars().any(|c| c != '0')).collect();
        if let Some(d) = disks.iter().find(|d| d.sas_address.as_ref().is_some_and(|a| addrs.contains(&norm_sas(a)))) {
            return Some(d);
        }
    }
    let (hctl, slot) = (hctl?, slot? as u32);
    disks.iter().find(|d| d.kernel_slot.as_ref().is_some_and(|(e, n)| e == hctl && *n == slot))
}

pub fn build(read: &EnclosureRead, disks: &[DiskInfo]) -> EnclosureReport {
    let mut errors = read.errors.clone();
    let identity = identity_from_raw(&read.identity);
    let cfg = read.page(0x01).map(config::parse).transpose().unwrap_or_else(|e| {
        errors.push(e.to_string());
        None
    });
    let mut rep = EnclosureReport {
        device: read.device.clone(),
        hctl: read.hctl.clone(),
        read_at: read.read_at,
        identity,
        supported: read.supported.clone(),
        vendor_pages: read.vendor_pages(),
        config: cfg.clone(),
        page_flags: Vec::new(),
        groups: Vec::new(),
        elements: Vec::new(),
        errors,
        led: LedReport { indicator_on: None, headline: String::new(), reasons: Vec::new(), hints: Vec::new() },
    };
    let Some(cfg) = cfg else {
        rep.led = explain(&rep);
        return rep;
    };
    let mut err = |e: crate::ses::ParseError| rep.errors.push(e.to_string());
    let st = read.page(0x02).and_then(|d| status::parse(d, &cfg).map_err(&mut err).ok());
    let desc = read.page(0x07).and_then(|d| descriptor::parse(d, &cfg).map_err(&mut err).ok());
    let add = read.page(0x0A).and_then(|d| addl::parse(d, &cfg).map_err(&mut err).ok());

    if let Some(st) = &st {
        for (on, name) in [(st.unrecov, "UNRECOV"), (st.crit, "CRIT"), (st.non_crit, "NON-CRIT"), (st.info, "INFO"), (st.invop, "INVOP")] {
            if on {
                rep.page_flags.push(name);
            }
        }
    }

    let mut index = 0;
    for (ti, th) in cfg.types.iter().enumerate() {
        let t = th.element_type;
        let n = th.possible_elements as usize;
        let overall = st.as_ref().map(|s| s.types[ti].0.clone());
        let mut group = Group {
            type_code: t,
            type_name: element_type_name(t),
            text: th.text.clone(),
            subenclosure: th.subenclosure_id,
            overall,
            overall_descriptor: desc.as_ref().map(|d| d.types[ti].0.clone()).unwrap_or_default(),
            elements: Vec::new(),
        };
        for i in 0..n {
            let status = st.as_ref().map(|s| s.types[ti].1[i].clone()).unwrap_or_else(|| status::parse_element(t, [6, 0, 0, 0]));
            let descriptor = desc.as_ref().map(|d| d.types[ti].1[i].clone()).unwrap_or_default();
            let addl = add.as_ref().and_then(|a| a.descriptors.iter().find(|x| x.element_index == Some(index)).cloned());
            let slot_number = ElementType(t).is_slot().then(|| {
                let from_addl = match addl.as_ref().and_then(|a| a.sas.as_ref()) {
                    Some(SasInfo::Slot { device_slot_number: Some(n), .. }) => Some(*n),
                    _ => None,
                };
                let from_status = match status.detail {
                    ElementDetail::Slot { slot_address: Some(a), .. } => Some(a),
                    _ => None,
                };
                from_addl.or(from_status).unwrap_or(i as u8)
            });
            let disk = if ElementType(t).is_slot() { slot_disk(addl.as_ref(), slot_number, rep.hctl.as_deref(), disks).cloned() } else { None };
            let name = if descriptor.is_empty() { default_name(t, i, n) } else { descriptor.clone() };
            let reporting = t == T::ESC_ELECTRONICS && status.bits.contains(&"REPORT");
            rep.elements.push(Element {
                index,
                type_code: t,
                type_name: element_type_name(t),
                type_index: i,
                subenclosure: th.subenclosure_id,
                flags: element_flags(t, &status),
                descriptor,
                name,
                status,
                addl,
                slot_number,
                disk,
                reporting,
            });
            group.elements.push(index);
            index += 1;
        }
        rep.groups.push(group);
    }
    rep.led = explain(&rep);
    rep
}


fn explain(rep: &EnclosureReport) -> LedReport {
    let mut reasons = Vec::new();
    let mut hints = Vec::new();

    let enc: Vec<&Element> = rep.of_type(&[T::ENCLOSURE]).collect();
    let indicator_on = enc.iter().find_map(|e| match e.status.detail {
        ElementDetail::Enclosure { failure_indication, warning_indication, .. } => Some(failure_indication || warning_indication),
        _ => None,
    });

    for f in &rep.page_flags {
        let (level, text) = match *f {
            "UNRECOV" => (Level::Unrecoverable, "enclosure reports an UNRECOVERABLE condition somewhere"),
            "CRIT" => (Level::Critical, "enclosure reports a CRITICAL condition somewhere"),
            "NON-CRIT" => (Level::Noncritical, "enclosure reports a NONCRITICAL condition somewhere"),
            "INFO" => (Level::Info, "INFO bit set (status changed since last read)"),
            _ => (Level::Info, "INVOP: a previous control operation was invalid"),
        };
        reasons.push(Reason { level, source: "Status page header".into(), text: text.into() });
    }
    for e in &rep.elements {
        for f in e.flags.iter().filter(|f| f.level > Level::Info) {
            reasons.push(Reason { level: f.level, source: e.name.clone(), text: f.text.clone() });
        }
    }
    // Overall elements can carry status too.
    for g in &rep.groups {
        if let Some(o) = &g.overall {
            for f in element_flags(g.type_code, o).into_iter().filter(|f| f.level > Level::Info) {
                reasons.push(Reason { level: f.level, source: format!("{} (overall)", g.type_name), text: f.text });
            }
        }
    }
    reasons.sort_by_key(|r| std::cmp::Reverse(r.level));

    let missing: Vec<&str> = rep
        .elements
        .iter()
        .filter(|e| matches!(e.type_code, T::POWER_SUPPLY | T::ESC_ELECTRONICS | T::COOLING) && e.status.code == 5)
        .map(|e| e.name.as_str())
        .collect();
    if !missing.is_empty() {
        hints.push(format!(
            "Reported NOT INSTALLED: {}. If those bays are physically populated, the IOM cannot see them (seating, dead module or a backplane/IOM fault); if they are empty, NetApp shelves commonly light the fault LED for an empty PSU/IOM bay.",
            missing.join(", ")
        ));
    }
    if rep.elements.iter().any(|e| e.status.bits.iter().any(|b| b.ends_with("REQUESTED") || *b == "FAULT REQSTD")) {
        hints.push("Some indicators were REQUESTED by a host (e.g. an old NetApp controller or a previous owner) — these stay latched until cleared with SES control (Phase 2) or a shelf power cycle.".into());
    }
    let fans: Vec<(u8, u32)> = rep
        .elements
        .iter()
        .filter_map(|e| match e.status.detail {
            ElementDetail::Fan { speed_code, rpm, .. } if e.status.code == 1 || e.status.code == 3 => Some((speed_code, rpm)),
            _ => None,
        })
        .collect();
    let max_temp = rep.elements.iter().filter_map(|e| match e.status.detail {
        ElementDetail::Temperature { celsius } => celsius,
        _ => None,
    }).max();
    if !fans.is_empty() && fans.iter().all(|(c, _)| *c >= 6) {
        let t = max_temp.map(|t| format!(" while the hottest sensor reads {t} °C")).unwrap_or_default();
        hints.push(format!(
            "All fans are at speed code 6–7 (second highest/highest){t}. IOMs normally pin the fans high while they consider a component failed or missing, so clearing the fault cause above is the first thing to try before manual fan control (Phase 2)."
        ));
    }
    if !rep.vendor_pages.is_empty() {
        hints.push(format!(
            "Vendor-specific pages present: {}. NetApp may keep extra fault state there (dumped for reverse engineering).",
            rep.vendor_pages.iter().map(|p| format!("{p:#04x}")).collect::<Vec<_>>().join(", ")
        ));
    }

    let serious: Vec<&Reason> = reasons.iter().filter(|r| r.level >= Level::Noncritical).collect();
    let headline = match (indicator_on, serious.first()) {
        (_, Some(top)) => format!(
            "Fault LED cause: {} — {}{}",
            top.source,
            top.text,
            if serious.len() > 1 { format!(" (+{} more)", serious.len() - 1) } else { String::new() }
        ),
        (Some(true), None) => "The enclosure reports its fault indicator ON but no standard element explains it — the cause is likely IOM-internal (see vendor pages and hints).".into(),
        (Some(false), None) => "SES reports the fault indicator OFF and no element faults. If the LED is lit, it is driven outside standard SES (vendor state, IOM firmware or a missing/mismatched partner IOM).".into(),
        (None, None) if rep.config.is_none() => "Could not read the configuration page — no explanation possible.".into(),
        (None, None) => "No enclosure element and no faults in standard pages; check hints and vendor pages.".into(),
    };
    LedReport { indicator_on, headline, reasons, hints }
}

/// One physical shelf (enclosure logical id) seen through one or more IOMs.
#[derive(Debug, Clone, Serialize)]
pub struct Shelf {
    pub logical_id: String,
    pub devices: Vec<EnclosureReport>,
    pub findings: Vec<Reason>,
}

impl Shelf {
    /// The device used to draw the shelf: the first one with parsed elements.
    pub fn primary(&self) -> &EnclosureReport {
        self.devices.iter().find(|d| !d.elements.is_empty()).unwrap_or(&self.devices[0])
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub taken_at: DateTime<Utc>,
    pub shelves: Vec<Shelf>,
    pub disks: Vec<DiskInfo>,
    pub errors: Vec<String>,
}

pub fn group_shelves(reports: Vec<EnclosureReport>) -> Vec<Shelf> {
    let mut shelves: Vec<Shelf> = Vec::new();
    for r in reports {
        let id = r.logical_id().unwrap_or(&r.device).to_string();
        match shelves.iter_mut().find(|s| s.logical_id == id) {
            Some(s) => s.devices.push(r),
            None => shelves.push(Shelf { logical_id: id, devices: vec![r], findings: Vec::new() }),
        }
    }
    for s in &mut shelves {
        let revs: Vec<(String, String)> = s.devices.iter().filter_map(|d| Some((d.device.clone(), d.firmware()?.to_string()))).collect();
        let mut uniq: Vec<&String> = revs.iter().map(|(_, r)| r).collect();
        uniq.sort();
        uniq.dedup();
        if uniq.len() > 1 {
            s.findings.push(Reason {
                level: Level::Noncritical,
                source: "IOM firmware".into(),
                text: format!(
                    "IOMs run different firmware ({}). NetApp expects matching IOM firmware; a mismatch is a common reason for a lit fault LED and fans held high.",
                    revs.iter().map(|(d, r)| format!("{d}: {r}")).collect::<Vec<_>>().join(", ")
                ),
            });
        }
        if s.devices.len() == 1 {
            let iom_count = s.devices[0].of_type(&[T::ESC_ELECTRONICS]).count();
            if iom_count > 1 {
                s.findings.push(Reason {
                    level: Level::Info,
                    source: "Cabling".into(),
                    text: "Only one IOM is visible to this host, so the other IOM's firmware can only be inferred from SES data of this one.".into(),
                });
            }
        }
    }
    shelves
}
