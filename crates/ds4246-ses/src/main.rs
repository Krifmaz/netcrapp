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
        Cmd::Demo => {
            let snap = live::snapshot_from_reads(&[synthetic::read()], synthetic::disks(), vec!["SYNTHETIC DATA — not from real hardware".into()]);
            print!("{}", text::render(&snap));
        }
    }
    Ok(())
}
