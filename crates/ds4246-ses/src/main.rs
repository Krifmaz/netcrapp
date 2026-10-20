//! Read-only debug CLI. The web dashboard (`ds4246-web`) is the main interface.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ds4246_core::{collect, discover, live, synthetic, text};

#[derive(Parser)]
#[command(version, about = "Read-only SES mapper for the NetApp DS4246 (Phase 1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List SCSI generic devices and mark enclosures (type 0x0D).
    List,
    /// Read every listed page from every enclosure and print the summary.
    Scan {
        /// Print the full parsed snapshot as JSON instead.
        #[arg(long)]
        json: bool,
        /// Skip drive temperature reads (LOG SENSE).
        #[arg(long)]
        no_temps: bool,
    },
    /// Like scan, and save raw pages to <out>/<device>/<timestamp>/.
    Dump {
        #[arg(long, default_value = "dumps")]
        out: PathBuf,
    },
    /// Re-parse saved dump directories offline (no root needed).
    Decode {
        dirs: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print the summary for built-in SYNTHETIC pages (no hardware).
    Demo,
    /// Phase 2: show fans, or request a fan speed code (the only write).
    #[command(subcommand)]
    Fan(FanCmd),
    /// Phase 3: read IOM buffers with READ BUFFER (modes 02h/03h only).
    #[command(subcommand)]
    Fw(FwCmd),
    /// Re-read SES pages on an interval and print every byte that changes.
    /// Read-only; for working out vendor counters. Ctrl-C to stop.
    Watch {
        /// Enclosure sg device, e.g. sg0.
        device: String,
        /// Page codes in hex.
        #[arg(long, value_delimiter = ',', default_value = "80,81")]
        pages: Vec<String>,
        /// Seconds between reads.
        #[arg(long, default_value_t = 30)]
        interval: u64,
    },
}

#[derive(Subcommand)]
enum FanCmd {
    /// Print each fan's RPM and actual speed code (read-only).
    Show { device: String },
    /// WRITE: SEND DIAGNOSTIC page 0x02 requesting speed code 1-7 on the fans,
    /// then watch the result for 60 s. Undo by requesting the previous code.
    Set {
        device: String,
        #[arg(long)]
        code: u8,
        /// Only this fan (1-based); default all.
        #[arg(long)]
        fan: Option<usize>,
        /// Required: confirms you want to send a control command.
        #[arg(long)]
        yes_write: bool,
    },
}

fn fan(cmd: FanCmd) -> Result<()> {
    use ds4246_core::control;
    use ds4246_core::sg::SgDevice;
    let show = |fans: &[control::FanReading]| {
        fans.iter().map(|f| format!("{} {}rpm c{}", f.name, f.rpm, f.speed_code)).collect::<Vec<_>>().join("  ")
    };
    match cmd {
        FanCmd::Show { device } => {
            let dev = SgDevice::open(format!("/dev/{device}"))?;
            let (_, _, fans) = control::read_fans(&dev)?;
            println!("{}", show(&fans));
        }
        FanCmd::Set { device, code, fan, yes_write } => {
            if !yes_write {
                bail!("this sends SEND DIAGNOSTIC to the enclosure; add --yes-write to confirm");
            }
            let dev = SgDevice::open(format!("/dev/{device}"))?;
            let (_, _, before) = control::read_fans(&dev)?;
            println!("before: {}", show(&before));
            let target = fan.map(|f| f.checked_sub(1).ok_or_else(|| anyhow::anyhow!("--fan is 1-based"))).transpose()?;
            control::set_fan_speed(&dev, code, target)?;
            println!("sent: requested speed code {code} on {}", fan.map(|f| format!("fan {f}")).unwrap_or("all fans".into()));
            for t in (10..=60).step_by(10) {
                std::thread::sleep(std::time::Duration::from_secs(10));
                let (_, _, now) = control::read_fans(&dev)?;
                println!("t+{t:>2}s:  {}", show(&now));
            }
        }
    }
    Ok(())
}

#[derive(Subcommand)]
enum FwCmd {
    /// List buffer IDs and capacities (READ BUFFER mode 03h, 4 bytes each).
    Probe { device: String },
    /// Read one buffer (mode 02h), twice, and save + analyse it if both reads match.
    Read {
        device: String,
        #[arg(long)]
        id: u8,
        /// Stop after this many MiB.
        #[arg(long, default_value_t = 32)]
        max_mib: u32,
        #[arg(long, default_value = "dumps")]
        out: PathBuf,
    },
    /// Analyse a saved image (no device access).
    Analyze { file: PathBuf },
}

fn fw(cmd: FwCmd) -> Result<()> {
    use ds4246_core::fw;
    use ds4246_core::sg::SgDevice;
    match cmd {
        FwCmd::Probe { device } => {
            let dev = SgDevice::open(format!("/dev/{device}"))?;
            let bufs = fw::probe(&dev);
            if bufs.is_empty() {
                println!("no buffer reports a capacity; diagnosis (read-only):");
                print!("{}", fw::diagnose(&dev));
            }
            for b in &bufs {
                println!("buffer id {:#04x}  capacity {:>9} bytes ({:#08x})  offset boundary 2^{}", b.id, b.capacity, b.capacity, b.offset_boundary);
            }
            if fw::ids_look_ignored(&bufs) {
                println!("note: every ID reports the same size — the device probably ignores BUFFER ID; use --id 0");
            }
        }
        FwCmd::Read { device, id, max_mib, out } => {
            let dev = SgDevice::open(format!("/dev/{device}"))?;
            let saved = fw::read_and_save(&dev, &device, id, max_mib.saturating_mul(1 << 20), &out, |pass, done, total| {
                eprint!("\rpass {pass}: {done}/{total} bytes");
            })?;
            eprintln!();
            print!("{}", saved.report);
            println!("\nsaved {} (never commit this file)", saved.path.display());
        }
        FwCmd::Analyze { file } => print!("{}", fw::analyze(&std::fs::read(file)?)),
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::List => {
            let all = discover::list_sg();
            if all.is_empty() {
                bail!("no /sys/class/scsi_generic entries (is the sg module loaded?)");
            }
            for s in all {
                let tag = if s.device_type == Some(0x0D) { "ENCLOSURE" } else { "" };
                println!(
                    "{:<6} [{}] type {:<4} {:<8} {:<16} {:<5} {:<6} {}",
                    s.name,
                    s.hctl.as_deref().unwrap_or("?"),
                    s.device_type.map(|t| format!("{t:#04x}")).unwrap_or_else(|| "?".into()),
                    s.vendor,
                    s.model,
                    s.rev,
                    s.block.as_deref().unwrap_or("-"),
                    tag
                );
            }
        }
        Cmd::Scan { json, no_temps } => {
            let reads = live::read_all(true);
            let snap = live::snapshot_from_reads(&reads, live::disks(!no_temps), Vec::new());
            if json {
                println!("{}", serde_json::to_string_pretty(&snap)?);
            } else {
                print!("{}", text::render(&snap));
            }
        }
        Cmd::Dump { out } => {
            let reads = live::read_all(true);
            if reads.is_empty() {
                bail!("no enclosure devices found");
            }
            let snap = live::snapshot_from_reads(&reads, live::disks(true), Vec::new());
            let summary = text::render(&snap);
            print!("{summary}");
            for r in &reads {
                let dir = collect::save_dump(&out, r, &summary)?;
                println!("saved {} pages from {} to {}", r.pages.len(), r.device, dir.display());
            }
        }
        Cmd::Decode { dirs, json } => {
            let reads = dirs.iter().map(|d| collect::load_dump(d)).collect::<std::io::Result<Vec<_>>>()?;
            let snap = live::snapshot_from_reads(&reads, Vec::new(), Vec::new());
            if json {
                println!("{}", serde_json::to_string_pretty(&snap)?);
            } else {
                print!("{}", text::render(&snap));
            }
        }
        Cmd::Watch { device, pages, interval } => watch(&device, &pages, interval)?,
        Cmd::Fw(c) => fw(c)?,
        Cmd::Fan(c) => fan(c)?,
        Cmd::Demo => {
            let snap = live::snapshot_from_reads(&[synthetic::read()], synthetic::disks(), vec!["SYNTHETIC DATA — not from real hardware".into()]);
            print!("{}", text::render(&snap));
        }
    }
    Ok(())
}

fn watch(device: &str, pages: &[String], interval: u64) -> Result<()> {
    use ds4246_core::sg::{receive_diag_cdb, SgDevice};
    let codes: Vec<u8> = pages.iter().map(|p| u8::from_str_radix(p.trim_start_matches("0x"), 16)).collect::<Result<_, _>>()?;
    let dev = SgDevice::open(format!("/dev/{device}"))?;
    let mut last: Vec<Option<Vec<u8>>> = vec![None; codes.len()];
    let start = std::time::Instant::now();
    println!("watching {device} pages {pages:?} every {interval}s (offset: old -> new)");
    loop {
        let t = start.elapsed().as_secs();
        for (i, &code) in codes.iter().enumerate() {
            let now = match dev.read_cdb(&receive_diag_cdb(code, 65532), 65532) {
                Ok(d) => d,
                Err(e) => {
                    println!("t+{t:>6}s page {code:02x}: {e}");
                    continue;
                }
            };
            if let Some(prev) = &last[i] {
                let changes: Vec<String> = now
                    .iter()
                    .enumerate()
                    .filter(|(j, b)| prev.get(*j) != Some(b))
                    .map(|(j, b)| format!("{j:#05x}: {:02x}->{b:02x}", prev.get(j).copied().unwrap_or(0)))
                    .collect();
                if !changes.is_empty() {
                    println!("t+{t:>6}s page {code:02x}: {}", changes.join("  "));
                }
            }
            last[i] = Some(now);
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}
