//! Plain-text summary used by the CLI and saved as `summary.txt` in dumps.

use std::fmt::Write;

use crate::report::{Element, EnclosureReport, Level, Snapshot};
use crate::ses::status::ElementDetail;
use crate::ses::types::ElementType as T;

pub fn element_value(e: &Element) -> String {
    match &e.status.detail {
        ElementDetail::Fan { rpm, speed_code, speed_name, .. } => format!("{rpm} rpm, speed code {speed_code} ({speed_name})"),
        ElementDetail::Temperature { celsius: Some(c) } => format!("{c} °C"),
        ElementDetail::Voltage { volts } => format!("{volts:.2} V"),
        ElementDetail::Current { amps } => format!("{amps:.2} A"),
        ElementDetail::Display { mode, character } => {
            let [a, b] = character.to_be_bytes();
            let ch = |c: u8| if (0x20..0x7f).contains(&c) { c as char } else { '.' };
            format!("mode {mode}, chars {:#06x} '{}{}'", character, ch(a), ch(b))
        }
        ElementDetail::Connector { connector_type_name, physical_link, .. } => format!("{connector_type_name}, link {physical_link:#04x}"),
        _ => String::new(),
    }
}

fn flags(e: &Element) -> String {
    e.flags.iter().map(|f| format!("[{}] {}", f.level.label(), f.text)).collect::<Vec<_>>().join("; ")
}

fn line(out: &mut String, e: &Element) {
    let extra = [element_value(e), e.status.bits.join(","), flags(e)].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("  ");
    let marker = match e.worst() {
        Some(l) if l >= Level::Noncritical => "!!",
        Some(Level::Ident) => " *",
        _ => "  ",
    };
    let _ = writeln!(out, "  {marker} {:<22} {:<14} {extra}", e.name, e.status.code_name);
}

pub fn render_enclosure(out: &mut String, r: &EnclosureReport) {
    let inq = r.identity.inquiry.as_ref();
    let _ = writeln!(
        out,
        "Enclosure {} [{}]  {} {}  firmware {}",
        r.device,
        r.hctl.as_deref().unwrap_or("?"),
        inq.map(|i| i.vendor.as_str()).unwrap_or("?"),
        inq.map(|i| i.product.as_str()).unwrap_or("?"),
        inq.map(|i| i.revision.as_str()).unwrap_or("?"),
    );
    if let Some(cfg) = &r.config {
        for s in &cfg.subenclosures {
            let _ = writeln!(out, "  subenclosure {}: {} {} rev {} (ES process {}/{})", s.id, s.vendor, s.product, s.revision, s.relative_es_process_id, s.num_es_processes);
        }
    }
    let hex = |v: &[u8]| v.iter().map(|p| format!("{p:02x}")).collect::<Vec<_>>().join(" ");
    let _ = writeln!(out, "  supported pages: {}", hex(&r.supported));
    let _ = writeln!(out, "  vendor pages:    {}", if r.vendor_pages.is_empty() { "none".into() } else { hex(&r.vendor_pages) });
    if !r.page_flags.is_empty() {
        let _ = writeln!(out, "  status page header: {}", r.page_flags.join(" "));
    }
    let _ = writeln!(out, "\n  FAULT LED: {}", r.led.headline);
    match r.led.indicator_on {
        Some(on) => {
            let _ = writeln!(out, "  (Enclosure element failure/warning indicator: {})", if on { "ON" } else { "off" });
        }
        None => out.push_str("  (no Enclosure element reported)\n"),
    }
    for reason in &r.led.reasons {
        let _ = writeln!(out, "    [{:<7}] {}: {}", reason.level.label(), reason.source, reason.text);
    }
    for h in &r.led.hints {
        let _ = writeln!(out, "    hint: {h}");
    }

    let sections: &[(&str, &[u8])] = &[
        ("IOMs", &[T::ESC_ELECTRONICS]),
        ("Power supplies", &[T::POWER_SUPPLY]),
        ("Fans", &[T::COOLING]),
        ("Temperatures", &[T::TEMPERATURE]),
        ("Voltages / currents", &[T::VOLTAGE, T::CURRENT]),
        ("Enclosure / display / alarm", &[T::ENCLOSURE, T::DISPLAY, T::AUDIBLE_ALARM]),
        ("Drive bays", &[T::DEVICE_SLOT, T::ARRAY_DEVICE_SLOT]),
    ];
    let mut shown = Vec::new();
    for (title, types) in sections {
        let els: Vec<&Element> = r.of_type(types).collect();
        if els.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n  -- {title} --");
        for e in els {
            line(out, e);
            if let Some(d) = &e.disk {
                let _ = writeln!(
                    out,
                    "       {} {}{}",
                    d.block.as_deref().unwrap_or(&d.sg),
                    d.display_model,
                    d.temperature_c.map(|t| format!(" {t} °C")).unwrap_or_default()
                );
            }
            shown.push(e.index);
        }
    }
    let rest: Vec<&Element> = r.elements.iter().filter(|e| !shown.contains(&e.index)).collect();
    if !rest.is_empty() {
        let _ = writeln!(out, "\n  -- Other elements --");
        for e in rest {
            line(out, e);
        }
    }
    for e in &r.errors {
        let _ = writeln!(out, "  error: {e}");
    }
}

pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DS4246 SES snapshot {}", s.taken_at.format("%Y-%m-%d %H:%M:%S UTC"));
    if s.shelves.is_empty() {
        out.push_str("No enclosure (peripheral type 0x0D) devices found.\n");
    }
    for shelf in &s.shelves {
        let _ = writeln!(out, "\n==== Shelf {} ({} IOM path(s)) ====", shelf.logical_id, shelf.devices.len());
        for f in &shelf.findings {
            let _ = writeln!(out, "  [{:<7}] {}: {}", f.level.label(), f.source, f.text);
        }
        for d in &shelf.devices {
            out.push('\n');
            render_enclosure(&mut out, d);
        }
    }
    for e in &s.errors {
        let _ = writeln!(out, "error: {e}");
    }
    out
}
