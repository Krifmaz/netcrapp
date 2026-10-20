//! Server-rendered HTML (maud). The JS only swaps fragments in and out.

use chrono::{DateTime, Utc};
use ds4246_core::collect::EnclosureRead;
use ds4246_core::hexdump::hexdump;
use ds4246_core::report::{Element, EnclosureReport, Level, Shelf, Snapshot};
use ds4246_core::ses::status::ElementDetail;
use ds4246_core::ses::types::ElementType as T;
use ds4246_core::text::element_value;
use maud::{html, Markup, DOCTYPE};

use crate::state::Data;

fn ts(t: Option<DateTime<Utc>>) -> String {
    t.map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_else(|| "never".into())
}

fn level_class(l: Option<Level>) -> &'static str {
    match l {
        Some(Level::Unrecoverable | Level::Critical) => "crit",
        Some(Level::Fail) => "fail",
        Some(Level::Noncritical) => "warn",
        Some(Level::Ident) => "ident",
        Some(Level::Info) => "info",
        None => "ok",
    }
}

fn status_class(e: &Element) -> &'static str {
    match (e.status.code, e.worst()) {
        (_, Some(l)) if l >= Level::Noncritical => level_class(Some(l)),
        (5, _) => "empty",
        (0 | 6 | 7 | 8, _) => "unknown",
        (_, Some(Level::Ident)) => "ident",
        _ => "ok",
    }
}

fn badge(l: Level) -> Markup {
    html! { span class={"badge " (level_class(Some(l)))} { (l.label()) } }
}

pub fn page(title: &str, body: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) }
                link rel="stylesheet" href="/static/app.css";
                script src="/static/app.js" defer {}
            }
            body { (body) }
        }
    }
}

pub fn login(error: Option<&str>) -> Markup {
    page("DS4246 — login", html! {
        main class="login" {
            h1 { "DS4246 shelf" }
            form method="post" action="/login" {
                label for="pw" { "Password" }
                input id="pw" type="password" name="password" autocomplete="current-password" autofocus required;
                button type="submit" { "Log in" }
            }
            @if let Some(e) = error { p class="error" { (e) } }
        }
    })
}

pub fn shell(poll_secs: u64, banner: Option<String>) -> Markup {
    page("DS4246 shelf", html! {
        header class="top" data-poll=(poll_secs) {
            h1 { "DS4246" span class="sub" { " · SES Phase 1 (read-only)" } }
            nav {
                button class="tab active" data-tab="dash" { "Dashboard" }
                button class="tab" data-tab="elements" { "All elements" }
                button class="tab" data-tab="raw" { "Raw pages" }
                button class="tab" data-tab="controls" { "Controls" }
            }
            div class="actions" {
                span id="live" class="live" { "live" }
                button id="pause" { "Pause" }
                button id="rescan" title="Read every listed page now (INQUIRY, VPD, all SES pages)" { "Full re-read" }
                button id="dump" title="Full re-read and save raw pages to the dump directory" { "Save dump" }
                form method="post" action="/logout" { button type="submit" { "Log out" } }
            }
        }
        @if let Some(b) = banner { div class="banner" { (b) } }
        div id="msg" class="msg" hidden {}
        main {
            section id="tab-dash" class="pane" data-src="/frag/dashboard" data-auto="1" { p { "Loading…" } }
            section id="tab-elements" class="pane" data-src="/frag/elements" data-auto="1" hidden {}
            section id="tab-raw" class="pane" data-src="/frag/raw" hidden {}
            section id="tab-controls" class="pane" hidden { (controls()) }
        }
    })
}

fn controls() -> Markup {
    html! {
        div class="card phase2" {
            h2 { "Phase 2 controls" }
            p class="muted" { "Disabled: Phase 1 is read-only. These are placeholders; no control endpoints exist on the server and no SEND DIAGNOSTIC is ever issued." }
            fieldset disabled {
                legend { "Fan speed" }
                label { "Requested speed code " select { @for c in 1..=7 { option { (c) } } } }
                button { "Apply" }
            }
            fieldset disabled {
                legend { "Drive LEDs" }
                label { "Bay " select { @for b in 0..24 { option { (b) } } } }
                button { "Identify on" } button { "Identify off" } button { "Fault off" }
            }
            fieldset disabled {
                legend { "Enclosure fault" }
                button { "Clear failure/warning request" }
            }
        }
    }
}

pub fn dashboard(data: &Data) -> Markup {
    let Some(snap) = &data.snapshot else {
        return html! { p { "No data yet." } @if let Some(e) = &data.error { p class="error" { (e) } } };
    };
    html! {
        p class="muted stamp" { "Polled " (ts(data.last_poll)) " · full read " (ts(data.last_full)) }
        @if let Some(e) = &data.error { p class="error" { "Last poll failed: " (e) } }
        @for e in &snap.errors { p class="banner" { (e) } }
        @if snap.shelves.is_empty() {
            div class="card" { h2 { "No enclosures found" } p { "No SCSI device with peripheral type 0x0D. Check cabling, `lsscsi -g`, and that the sg module is loaded." } }
        }
        @for shelf in &snap.shelves { (shelf_view(shelf, snap)) }
    }
}

fn shelf_view(shelf: &Shelf, snap: &Snapshot) -> Markup {
    let r = shelf.primary();
    let led = r.led.indicator_on;
    let display = r.of_type(&[T::DISPLAY]).next();
    let shelf_id = display.map(|d| match d.status.detail {
        ElementDetail::Display { character, .. } => {
            let [a, b] = character.to_be_bytes();
            let c = |x: u8| if (0x20..0x7f).contains(&x) { (x as char).to_string() } else { format!("{x:02x}") };
            format!("{}{}", c(a), c(b))
        }
        _ => "?".into(),
    });
    html! {
        div class="shelf" {
            div class="faceplate" {
                div class="ears" {
                    div class={"led " (match led { Some(true) => "amber", Some(false) => "off", None => "unknown" })} title="Front fault LED as reported by the Enclosure element" {}
                    span class="muted" { "fault" }
                    @if let Some(id) = &shelf_id { div class="shelfid" title="Display element character status" { (id) } }
                }
                div class="bays" { @for e in bays(r) { (bay(e)) } }
            }
            (faults(shelf, r))
            div class="grid" {
                (ioms(shelf))
                (psus(r))
                (fans(r))
                (temps(r))
                (volts(r))
            }
            @let unmapped: Vec<_> = snap.disks.iter().filter(|d| !r.elements.iter().any(|e| e.disk.as_ref().is_some_and(|x| x.sg == d.sg))).collect();
            @if !unmapped.is_empty() {
                details class="card" {
                    summary { "Disks not mapped to a bay (" (unmapped.len()) ")" }
                    ul { @for d in unmapped { li { (d.block.as_deref().unwrap_or(&d.sg)) " — " (d.vendor) " " (d.model) } } }
                }
            }
        }
    }
}

fn bays(r: &EnclosureReport) -> Vec<&Element> {
    let mut v: Vec<&Element> = r.of_type(&[T::ARRAY_DEVICE_SLOT, T::DEVICE_SLOT]).collect();
    v.sort_by_key(|e| e.slot_number.unwrap_or(u8::MAX));
    v
}

fn bay(e: &Element) -> Markup {
    let n = e.slot_number.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
    let tip = format!(
        "{} — {}{}{}",
        e.name,
        e.status.code_name,
        if e.status.bits.is_empty() { String::new() } else { format!(" [{}]", e.status.bits.join(", ")) },
        e.flags.iter().map(|f| format!("\n{}: {}", f.level.label(), f.text)).collect::<String>()
    );
    html! {
        div class={"bay " (status_class(e))} title=(tip) {
            div class="bayhead" {
                span class="num" { (n) @if e.status.ident { " " span class="identmark" { "IDENT" } } }
                span class="st" { (e.status.code_name) }
            }
            @match &e.disk {
                Some(d) => {
                    div class="model" { (d.model) }
                    div class="meta" {
                        span { (d.block.as_deref().unwrap_or(&d.sg)) }
                        @if let Some(t) = d.temperature_c { span class={"temp" @if t >= 50 { " hot" }} { (t) "°C" } }
                    }
                }
                None => {
                    div class="model muted" { @if e.status.code == 5 { "empty" } @else { "installed (not mapped)" } }
                }
            }
        }
    }
}

fn faults(shelf: &Shelf, r: &EnclosureReport) -> Markup {
    let cls = match r.led.indicator_on {
        Some(true) => "card faults on",
        _ if !r.led.reasons.is_empty() => "card faults on",
        _ => "card faults",
    };
    html! {
        div class=(cls) {
            h2 { "Why is the amber LED on?" }
            p class="headline" { (r.led.headline) }
            @if !r.page_flags.is_empty() { p class="muted" { "Status page summary bits: " (r.page_flags.join(" ")) } }
            @if !r.led.reasons.is_empty() || !shelf.findings.is_empty() {
                ul class="reasons" {
                    @for f in &shelf.findings { li { (badge(f.level)) " " b { (f.source) } ": " (f.text) } }
                    @for x in &r.led.reasons { li { (badge(x.level)) " " b { (x.source) } ": " (x.text) } }
                }
            }
            @if !r.led.hints.is_empty() {
                h3 { "Hints" }
                ul class="hints" { @for h in &r.led.hints { li { (h) } } }
            }
        }
    }
}

fn simple_row(e: &Element, value: Markup) -> Markup {
    html! {
        tr class=(status_class(e)) {
            td { (e.name) }
            td { span class={"pill " (status_class(e))} { (e.status.code_name) } }
            td { (value) }
            td class="bits" { (e.status.bits.join(", ")) }
        }
    }
}

fn table(title: &str, rows: Markup) -> Markup {
    html! {
        div class="card" {
            h2 { (title) }
            table { thead { tr { th { "Name" } th { "Status" } th { "Value" } th { "Bits" } } } tbody { (rows) } }
        }
    }
}

fn ioms(shelf: &Shelf) -> Markup {
    let r = shelf.primary();
    html! {
        div class="card" {
            h2 { "IOMs" }
            table {
                thead { tr { th { "Element" } th { "Status" } th { "Bits" } } }
                tbody {
                    @for e in r.of_type(&[T::ESC_ELECTRONICS]) {
                        tr class=(status_class(e)) {
                            td { (e.name) @if e.reporting { " " span class="muted" { "(answering on " (r.device) ")" } } }
                            td { span class={"pill " (status_class(e))} { (e.status.code_name) } }
                            td class="bits" { (e.status.bits.join(", ")) }
                        }
                    }
                }
            }
            h3 { "Firmware (per SES path)" }
            table {
                thead { tr { th { "sg" } th { "INQUIRY" } th { "Rev" } th { "Subencl. rev" } th { "Serial" } } }
                tbody {
                    @for d in &shelf.devices {
                        @let inq = d.identity.inquiry.as_ref();
                        tr {
                            td { (d.device) br; span class="muted" { (d.hctl.as_deref().unwrap_or("")) } }
                            td { (inq.map(|i| format!("{} {}", i.vendor, i.product)).unwrap_or_default()) }
                            td { b { (inq.map(|i| i.revision.as_str()).unwrap_or("?")) } }
                            td { (d.config.as_ref().and_then(|c| c.subenclosures.first()).map(|s| s.revision.as_str()).unwrap_or("?")) }
                            td { (d.identity.serial.as_deref().unwrap_or("?")) }
                        }
                    }
                }
            }
        }
    }
}

fn psus(r: &EnclosureReport) -> Markup {
    table("Power supplies", html! { @for e in r.of_type(&[T::POWER_SUPPLY]) { (simple_row(e, html! {})) } })
}

fn fans(r: &EnclosureReport) -> Markup {
    table("Fans", html! {
        @for e in r.of_type(&[T::COOLING]) {
            @let v = match e.status.detail { ElementDetail::Fan { rpm, speed_code, speed_name, .. } => Some((rpm, speed_code, speed_name)), _ => None };
            (simple_row(e, html! {
                @if let Some((rpm, code, name)) = v {
                    div class="fan" {
                        span { (rpm) " rpm" }
                        span class="muted" { " code " (code) " (" (name) ")" }
                        meter min="0" max="7" high="5" value=(code) {}
                    }
                }
            }))
        }
    })
}

fn temps(r: &EnclosureReport) -> Markup {
    table("Temperatures", html! { @for e in r.of_type(&[T::TEMPERATURE]) { (simple_row(e, html! { (element_value(e)) })) } })
}

fn volts(r: &EnclosureReport) -> Markup {
    let els: Vec<&Element> = r.of_type(&[T::VOLTAGE, T::CURRENT]).collect();
    if els.is_empty() {
        return html! {};
    }
    table("Voltage / current", html! { @for e in els { (simple_row(e, html! { (element_value(e)) })) } })
}

pub fn elements(data: &Data) -> Markup {
    let Some(snap) = &data.snapshot else { return html! { p { "No data yet." } } };
    html! {
        @for shelf in &snap.shelves {
            @for r in &shelf.devices {
                div class="card" {
                    h2 { "Elements via " (r.device) }
                    table class="elements" {
                        thead { tr { th { "#" } th { "Type" } th { "Name" } th { "Status" } th { "Value" } th { "Bits" } th { "Flags" } th { "Raw" } } }
                        tbody {
                            @for g in &r.groups {
                                tr class="group" {
                                    td colspan="8" {
                                        b { (g.type_name) } " (" (format!("{:#04x}", g.type_code)) ") · subenclosure " (g.subenclosure)
                                        @if !g.text.is_empty() { " · “" (g.text) "”" }
                                        @if let Some(o) = &g.overall { " · overall: " (o.code_name) " " span class="mono" { (hex4(&o.raw)) } }
                                    }
                                }
                                @for &i in &g.elements {
                                    @let e = &r.elements[i];
                                    tr class=(status_class(e)) {
                                        td { (e.index) }
                                        td { (e.type_name) }
                                        td { (e.name) @if let Some(n) = e.slot_number { span class="muted" { " slot " (n) } } }
                                        td { span class={"pill " (status_class(e))} { (e.status.code_name) } }
                                        td { (element_value(e)) }
                                        td class="bits" { (e.status.bits.join(", ")) }
                                        td { @for f in &e.flags { (badge(f.level)) " " (f.text) br; } }
                                        td class="mono" { (hex4(&e.status.raw)) }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn hex4(b: &[u8; 4]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

pub fn raw(data: &Data) -> Markup {
    html! {
        p class="muted" {
            "Pages 0x01/0x02/0x07/0x0A refresh on every poll; all other pages (vendor pages included) are re-read only by "
            b { "Full re-read" } " / " b { "Save dump" } " (in case a vendor page is read-and-clear). Last full read: " (ts(data.last_full))
        }
        @for r in &data.merged { (raw_device(r)) }
    }
}

fn raw_device(r: &EnclosureRead) -> Markup {
    html! {
        div class="card" {
            h2 { (r.device) " " span class="muted" { (r.hctl.as_deref().unwrap_or("")) } }
            p { "Supported (page 0x00): " span class="mono" { (r.supported.iter().map(|p| format!("{p:02x}")).collect::<Vec<_>>().join(" ")) } }
            p { "Vendor pages: " b class="mono" { (r.vendor_pages().iter().map(|p| format!("{p:#04x}")).collect::<Vec<_>>().join(" ")) } }
            @for (code, d) in r.identity.inquiry.iter().map(|d| ("INQUIRY".to_string(), d)).chain(r.identity.vpd.iter().filter_map(|(c, d)| Some((format!("VPD {c:#04x}"), d.as_ref().ok()?)))) {
                details { summary { (code) " · " (d.len()) " bytes" } pre { (hexdump(d)) } }
            }
            @for p in &r.pages {
                details class=(if p.vendor { "vendor" } else { "" }) {
                    summary {
                        span class="mono" { (format!("{:#04x}", p.code)) } " " (p.name)
                        @if p.vendor { " " span class="badge warn" { "vendor" } }
                        @match (&p.data, &p.error) {
                            (Some(d), _) => { " · " (d.len()) " bytes · " a href={"/raw/" (r.device) "/" (format!("{:02x}", p.code)) ".bin"} { "download .bin" } }
                            (None, Some(e)) => { " · " span class="error" { (e) } }
                            _ => {}
                        }
                    }
                    @if let Some(d) = &p.data { pre { (hexdump(d)) } }
                }
            }
        }
    }
}

pub fn message(ok: bool, text: &str) -> Markup {
    html! { span class=(if ok { "okmsg" } else { "error" }) { (text) } }
}
