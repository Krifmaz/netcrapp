//! One-call helpers that read live hardware and produce a [`Snapshot`].

use chrono::Utc;

use crate::collect::{read_enclosure, EnclosureRead};
use crate::discover;
use crate::report::{build, group_shelves, Snapshot};

pub fn snapshot_from_reads(reads: &[EnclosureRead], disks: Vec<discover::DiskInfo>, errors: Vec<String>) -> Snapshot {
    let reports = reads.iter().map(|r| build(r, &disks)).collect();
    Snapshot { taken_at: Utc::now(), shelves: group_shelves(reports), disks, errors }
}

/// Reads every enclosure. `full` reads all listed pages (plus INQUIRY/VPD);
/// otherwise only the standard status pages.
pub fn read_all(full: bool) -> Vec<EnclosureRead> {
    discover::enclosures().iter().map(|e| read_enclosure(e, full)).collect()
}

pub fn disks(temps: bool) -> Vec<discover::DiskInfo> {
    let mut d = discover::disks();
    if temps {
        discover::fill_temperatures(&mut d);
    }
    d
}
