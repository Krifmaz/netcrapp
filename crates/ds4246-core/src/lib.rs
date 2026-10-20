//! Read-only access to SES enclosures (built for the NetApp DS4246 / IOM6).
//!
//! Phase 1 rule: nothing in this crate can send a command that changes device
//! state; see [`sg::check_cdb`].

pub mod hexdump;
pub mod scsi;
pub mod ses;
pub mod sg;
pub mod collect;
pub mod discover;
pub mod report;
pub mod text;
pub mod live;
pub mod synthetic;
