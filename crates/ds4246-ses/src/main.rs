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
                println!("no buffer reports a capacity (READ BUFFER descriptor mode may be unsupported)");
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
            let info = fw::probe(&dev).into_iter().find(|b| b.id == id).ok_or_else(|| anyhow::anyhow!("buffer {id:#04x} not reported by probe"))?;
            let max = max_mib.saturating_mul(1 << 20);
            let mut images = Vec::new();
            for pass in 1..=2 {
                let (data, err) = fw::read(&dev, &info, max, |done, total| {
                    eprint!("\rpass {pass}: {done}/{total} bytes");
                });
                eprintln!();
                if let Some(e) = err {
                    println!("pass {pass} stopped at {} bytes: {e}", data.len());
                }
                images.push(data);
            }
            let (a, b) = (&images[0], &images[1]);
            let stable = a == b;
            let dir = out.join(&device).join(chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string()).join("fw");
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!("buffer_{id:02x}.bin"));
            std::fs::write(&path, a)?;
            if !stable {
                std::fs::write(dir.join(format!("buffer_{id:02x}.pass2.bin")), b)?;
            }
            let report = format!(
                "READ BUFFER mode 02h, buffer {id:#04x}, device {device}\ncapacity {} bytes, offset boundary 2^{}\npass1 {} bytes sha256 {}\npass2 {} bytes sha256 {}\nstable: {stable}\n\n{}",
                info.capacity,
                info.offset_boundary,
                a.len(),
                fw::sha256_hex(a),
                b.len(),
                fw::sha256_hex(b),
                fw::analyze(a)
            );
            std::fs::write(dir.join(format!("buffer_{id:02x}.report.txt")), &report)?;
            print!("{report}");
            println!("\nsaved {} (never commit this file)", path.display());
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
