//! Background SES polling. All hardware access is serialized through `hw`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use ds4246_core::collect::{self, EnclosureRead};
use ds4246_core::discover::{self, DiskInfo};
use ds4246_core::report::Snapshot;
use ds4246_core::{live, synthetic, text};

use crate::auth::Auth;
use crate::config::Config;

#[derive(Debug, Clone)]
pub enum Mode {
    Live,
    Replay(Vec<PathBuf>),
    Demo,
}

impl Mode {
    pub fn banner(&self) -> Option<String> {
        match self {
            Mode::Live => None,
            Mode::Replay(d) => Some(format!("REPLAY of saved dump(s): {}", d.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "))),
            Mode::Demo => Some("DEMO — synthetic data, not real hardware".into()),
        }
    }
}

#[derive(Default)]
pub struct Data {
    pub snapshot: Option<Snapshot>,
    /// Latest full read per device (all listed pages + INQUIRY/VPD).
    pub full_reads: Vec<EnclosureRead>,
    /// Full reads with the latest polled standard pages merged in.
    pub merged: Vec<EnclosureRead>,
    pub last_poll: Option<DateTime<Utc>>,
    pub last_full: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

pub struct AppState {
    pub cfg: Config,
    pub mode: Mode,
    pub auth: Auth,
    pub data: RwLock<Data>,
    hw: Mutex<HwCache>,
}

#[derive(Default)]
struct HwCache {
    temps: HashMap<String, Option<u8>>,
    temps_at: Option<Instant>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config, mode: Mode) -> Self {
        let auth = Auth::new(cfg.password_hash.clone(), Duration::from_secs(cfg.session_hours * 3600));
        Self { cfg, mode, auth, data: RwLock::default(), hw: Mutex::default() }
    }

    fn read(&self, full: bool) -> anyhow::Result<Vec<EnclosureRead>> {
        Ok(match &self.mode {
            Mode::Live => live::read_all(full),
            Mode::Replay(dirs) => dirs.iter().map(|d| collect::load_dump(d)).collect::<std::io::Result<_>>()?,
            Mode::Demo => vec![synthetic::read()],
        })
    }

    fn disks(&self, hw: &mut HwCache) -> Vec<DiskInfo> {
        match self.mode {
            Mode::Live => {}
            Mode::Demo => return synthetic::disks(),
            Mode::Replay(_) => return Vec::new(),
        }
        let mut disks = discover::disks();
        let every = self.cfg.drive_temp_secs;
        let due = every > 0 && hw.temps_at.is_none_or(|t| t.elapsed() >= Duration::from_secs(every));
        if due {
            discover::fill_temperatures(&mut disks);
            hw.temps = disks.iter().map(|d| (d.sg.clone(), d.temperature_c)).collect();
            hw.temps_at = Some(Instant::now());
        } else {
            for d in disks.iter_mut().filter(|d| d.temperature_c.is_none()) {
                d.temperature_c = hw.temps.get(&d.sg).copied().flatten();
            }
        }
        disks
    }

    /// Blocking: reads hardware and rebuilds the snapshot.
    pub fn refresh(&self, mut full: bool) -> anyhow::Result<()> {
        let mut hw = self.hw.lock().unwrap();
        if self.data.read().unwrap().full_reads.is_empty() {
            full = true;
        }
        let reads = match self.read(full) {
            Ok(r) => r,
            Err(e) => {
                self.data.write().unwrap().error = Some(e.to_string());
                return Err(e);
            }
        };
        let disks = self.disks(&mut hw);
        drop(hw);

        let mut data = self.data.write().unwrap();
        let now = Utc::now();
        if full {
            data.full_reads = reads.clone();
            data.last_full = Some(now);
        }
        let merged: Vec<EnclosureRead> = reads.iter().map(|r| merge(data.full_reads.iter().find(|f| f.device == r.device), r)).collect();
        data.snapshot = Some(live::snapshot_from_reads(&merged, disks, Vec::new()));
        data.merged = merged;
        data.last_poll = Some(now);
        data.error = None;
        Ok(())
    }

    /// Blocking: full read, then save one dump set per enclosure device.
    pub fn save_dump(&self) -> anyhow::Result<Vec<PathBuf>> {
        self.refresh(true)?;
        let data = self.data.read().unwrap();
        let summary = data.snapshot.as_ref().map(text::render).unwrap_or_default();
        let mut dirs = Vec::new();
        for r in &data.full_reads {
            dirs.push(collect::save_dump(&self.cfg.dump_dir, r, &summary)?);
        }
        Ok(dirs)
    }
}

impl AppState {
    fn enclosure_device(&self) -> anyhow::Result<String> {
        if !matches!(self.mode, Mode::Live) {
            anyhow::bail!("firmware reads need live hardware (not available in demo/replay mode)");
        }
        let data = self.data.read().unwrap();
        data.full_reads.first().map(|r| r.device.clone()).ok_or_else(|| anyhow::anyhow!("no enclosure device found"))
    }

    /// Blocking: READ BUFFER descriptor probe (mode 03h) on the enclosure.
    pub fn fw_probe(&self) -> anyhow::Result<(String, Vec<ds4246_core::fw::BufferInfo>)> {
        let device = self.enclosure_device()?;
        let _hw = self.hw.lock().unwrap();
        let dev = ds4246_core::sg::SgDevice::open(format!("/dev/{device}"))?;
        Ok((device, ds4246_core::fw::probe(&dev)))
    }

    /// Blocking: reads one buffer twice (mode 02h) and saves it in dump_dir.
    pub fn fw_read(&self, id: u8) -> anyhow::Result<ds4246_core::fw::SavedImage> {
        let device = self.enclosure_device()?;
        let _hw = self.hw.lock().unwrap();
        let dev = ds4246_core::sg::SgDevice::open(format!("/dev/{device}"))?;
        Ok(ds4246_core::fw::read_and_save(&dev, &device, id, 32 << 20, &self.cfg.dump_dir, |_, _, _| {})?)
    }

    /// Every file under dump_dir as (relative path, size), newest directories first.
    pub fn dump_files(&self) -> Vec<(String, u64)> {
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, u64)>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                match e.file_type() {
                    Ok(t) if t.is_dir() => walk(root, &p, out),
                    Ok(t) if t.is_file() => {
                        if let Ok(rel) = p.strip_prefix(root) {
                            out.push((rel.to_string_lossy().to_string(), e.metadata().map(|m| m.len()).unwrap_or(0)));
                        }
                    }
                    _ => {}
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.cfg.dump_dir, &self.cfg.dump_dir, &mut out);
        out.sort_by(|a, b| b.0.cmp(&a.0));
        out
    }

    /// Resolves a relative path inside dump_dir, refusing anything outside it.
    pub fn dump_file_path(&self, rel: &str) -> Option<PathBuf> {
        let root = std::fs::canonicalize(&self.cfg.dump_dir).ok()?;
        let p = std::fs::canonicalize(root.join(rel)).ok()?;
        (p.starts_with(&root) && p.is_file()).then_some(p)
    }
}

/// Overlays freshly polled pages on the last full read of the same device.
fn merge(full: Option<&EnclosureRead>, poll: &EnclosureRead) -> EnclosureRead {
    let Some(full) = full else { return poll.clone() };
    if poll.full {
        return poll.clone();
    }
    let mut m = full.clone();
    for p in &poll.pages {
        match m.pages.iter_mut().find(|x| x.code == p.code) {
            Some(slot) => *slot = p.clone(),
            None => m.pages.push(p.clone()),
        }
    }
    if !poll.supported.is_empty() {
        m.supported = poll.supported.clone();
    }
    m.read_at = poll.read_at;
    m.errors = poll.errors.clone();
    m
}

pub async fn poller(state: Shared) {
    let every = Duration::from_secs(state.cfg.poll_secs);
    loop {
        let s = state.clone();
        let static_source = !matches!(s.mode, Mode::Live);
        let res = tokio::task::spawn_blocking(move || s.refresh(false)).await;
        match res {
            Ok(Err(e)) => eprintln!("poll failed: {e:#}"),
            Err(e) => eprintln!("poll task panicked: {e}"),
            Ok(Ok(())) => {}
        }
        if static_source {
            // Replay/demo data never changes; read once.
            return;
        }
        tokio::time::sleep(every).await;
    }
}
