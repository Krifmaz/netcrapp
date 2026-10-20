//! Minimal SG_IO wrapper for `/dev/sg*`.
//!
//! This is the ONLY place a CDB reaches the kernel. It enforces the Phase 1
//! safety rules: an opcode allow-list, data-in transfers only, and the device
//! opened read-only.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use thiserror::Error;

const SG_IO: libc::c_ulong = 0x2285;
const SG_DXFER_FROM_DEV: libc::c_int = -3;
const SG_INFO_OK_MASK: u32 = 0x1;

pub const OP_INQUIRY: u8 = 0x12;
pub const OP_RECEIVE_DIAGNOSTIC: u8 = 0x1C;
pub const OP_LOG_SENSE: u8 = 0x4D;
pub const OP_READ_BUFFER: u8 = 0x3C;

/// READ BUFFER modes allowed (Phase 3): data and descriptor only. Vendor
/// mode 01h, echo buffers and error-history modes (which can create or clear
/// snapshots) are refused.
pub const READ_BUFFER_DATA: u8 = 0x02;
pub const READ_BUFFER_DESCRIPTOR: u8 = 0x03;

/// Opcodes this crate is allowed to send. Everything here moves data from the
/// device to the host and changes no device state.
pub const ALLOWED_OPCODES: &[u8] = &[OP_INQUIRY, OP_RECEIVE_DIAGNOSTIC, OP_LOG_SENSE, OP_READ_BUFFER];

#[repr(C)]
struct SgIoHdr {
    interface_id: libc::c_int,
    dxfer_direction: libc::c_int,
    cmd_len: libc::c_uchar,
    mx_sb_len: libc::c_uchar,
    iovec_count: libc::c_ushort,
    dxfer_len: libc::c_uint,
    dxferp: *mut c_void,
    cmdp: *const libc::c_uchar,
    sbp: *mut libc::c_uchar,
    timeout: libc::c_uint,
    flags: libc::c_uint,
    pack_id: libc::c_int,
    usr_ptr: *mut c_void,
    status: libc::c_uchar,
    masked_status: libc::c_uchar,
    msg_status: libc::c_uchar,
    sb_len_wr: libc::c_uchar,
    host_status: libc::c_ushort,
    driver_status: libc::c_ushort,
    resid: libc::c_int,
    duration: libc::c_uint,
    info: libc::c_uint,
}

#[derive(Debug, Error)]
pub enum SgError {
    #[error("refusing opcode {0:#04x}: not on the read-only allow-list")]
    Forbidden(u8),
    #[error("refusing LOG SENSE with SP (save parameters) set")]
    LogSenseSave,
    #[error("refusing READ BUFFER mode {0:#04x}: only 02h (data) and 03h (descriptor) are allowed")]
    ReadBufferMode(u8),
    #[error("open {path}: {source}")]
    Open { path: PathBuf, source: std::io::Error },
    #[error("SG_IO ioctl: {0}")]
    Ioctl(std::io::Error),
    #[error("SCSI status {status:#04x} host {host:#06x} driver {driver:#06x}{sense}")]
    Check { status: u8, host: u16, driver: u16, sense: String },
}

pub struct SgDevice {
    file: File,
    path: PathBuf,
    pub timeout_ms: u32,
}

impl SgDevice {
    /// Opens the sg node read-only. Root (CAP_SYS_RAWIO) is needed for SES.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SgError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .map_err(|source| SgError::Open { path: path.clone(), source })?;
        Ok(Self { file, path, timeout_ms: 20_000 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Issues a data-in CDB. Returns the bytes actually transferred.
    pub fn read_cdb(&self, cdb: &[u8], alloc: usize) -> Result<Vec<u8>, SgError> {
        check_cdb(cdb)?;
        let mut buf = vec![0u8; alloc];
        let mut sense = [0u8; 64];
        let mut hdr = SgIoHdr {
            interface_id: b'S' as libc::c_int,
            dxfer_direction: SG_DXFER_FROM_DEV,
            cmd_len: cdb.len() as u8,
            mx_sb_len: sense.len() as u8,
            iovec_count: 0,
            dxfer_len: alloc as u32,
            dxferp: buf.as_mut_ptr() as *mut c_void,
            cmdp: cdb.as_ptr(),
            sbp: sense.as_mut_ptr(),
            timeout: self.timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        // SAFETY: hdr points at live buffers sized as declared for the whole call.
        let rc = unsafe { libc::ioctl(self.file.as_raw_fd(), SG_IO as _, &mut hdr as *mut SgIoHdr) };
        if rc < 0 {
            return Err(SgError::Ioctl(std::io::Error::last_os_error()));
        }
        if hdr.info & SG_INFO_OK_MASK != 0 {
            let sense = &sense[..hdr.sb_len_wr as usize];
            return Err(SgError::Check {
                status: hdr.status,
                host: hdr.host_status,
                driver: hdr.driver_status,
                sense: describe_sense(sense),
            });
        }
        let got = alloc.saturating_sub(hdr.resid.max(0) as usize);
        buf.truncate(got);
        Ok(buf)
    }
}

/// Validates a CDB against the Phase 1 rules. Public so tests can prove it.
pub fn check_cdb(cdb: &[u8]) -> Result<(), SgError> {
    let op = *cdb.first().ok_or(SgError::Forbidden(0xFF))?;
    if !ALLOWED_OPCODES.contains(&op) {
        return Err(SgError::Forbidden(op));
    }
    if op == OP_LOG_SENSE && cdb.len() > 1 && cdb[1] & 0x01 != 0 {
        return Err(SgError::LogSenseSave);
    }
    if op == OP_READ_BUFFER {
        let mode = cdb.get(1).copied().unwrap_or(0xFF);
        if mode != READ_BUFFER_DATA && mode != READ_BUFFER_DESCRIPTOR {
            return Err(SgError::ReadBufferMode(mode));
        }
    }
    Ok(())
}

fn describe_sense(sense: &[u8]) -> String {
    if sense.is_empty() {
        return String::new();
    }
    let (key, asc, ascq) = match sense[0] & 0x7F {
        0x72 | 0x73 if sense.len() >= 4 => (sense[1] & 0x0F, sense[2], sense[3]),
        0x70 | 0x71 if sense.len() >= 14 => (sense[2] & 0x0F, sense[12], sense[13]),
        _ => return format!(", sense {}", crate::hexdump::hex_line(sense)),
    };
    let key_name = match key {
        0x0 => "NO SENSE",
        0x1 => "RECOVERED ERROR",
        0x2 => "NOT READY",
        0x3 => "MEDIUM ERROR",
        0x4 => "HARDWARE ERROR",
        0x5 => "ILLEGAL REQUEST",
        0x6 => "UNIT ATTENTION",
        0xB => "ABORTED COMMAND",
        _ => "OTHER",
    };
    format!(", sense {key_name} asc/ascq {asc:#04x}/{ascq:#04x}")
}

pub fn inquiry_cdb(vpd: Option<u8>, alloc: u16) -> [u8; 6] {
    let [hi, lo] = alloc.to_be_bytes();
    match vpd {
        Some(page) => [OP_INQUIRY, 0x01, page, hi, lo, 0],
        None => [OP_INQUIRY, 0x00, 0x00, hi, lo, 0],
    }
}

pub fn receive_diag_cdb(page: u8, alloc: u16) -> [u8; 6] {
    let [hi, lo] = alloc.to_be_bytes();
    [OP_RECEIVE_DIAGNOSTIC, 0x01, page, hi, lo, 0]
}

/// LOG SENSE, PC=01b (current cumulative), SP=0, PPC=0.
pub fn log_sense_cdb(page: u8, alloc: u16) -> [u8; 10] {
    let [hi, lo] = alloc.to_be_bytes();
    [OP_LOG_SENSE, 0x00, 0x40 | (page & 0x3F), 0, 0, 0, 0, hi, lo, 0]
}

/// READ BUFFER(10). `offset` and `len` are 24-bit.
pub fn read_buffer_cdb(mode: u8, id: u8, offset: u32, len: u32) -> [u8; 10] {
    let o = offset.to_be_bytes();
    let l = len.to_be_bytes();
    [OP_READ_BUFFER, mode, id, o[1], o[2], o[3], l[1], l[2], l[3], 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list() {
        assert!(check_cdb(&receive_diag_cdb(0x02, 100)).is_ok());
        assert!(check_cdb(&inquiry_cdb(Some(0x83), 100)).is_ok());
        assert!(check_cdb(&log_sense_cdb(0x0D, 100)).is_ok());
        assert!(check_cdb(&read_buffer_cdb(READ_BUFFER_DATA, 0, 0, 4096)).is_ok());
        assert!(check_cdb(&read_buffer_cdb(READ_BUFFER_DESCRIPTOR, 0, 0, 4)).is_ok());
        for mode in [0x00, 0x01, 0x0A, 0x0B, 0x1C, 0x1F] {
            assert!(matches!(check_cdb(&read_buffer_cdb(mode, 0, 0, 4)), Err(SgError::ReadBufferMode(_))));
        }
        // SEND DIAGNOSTIC, WRITE BUFFER, FORMAT, WRITE(10), MODE SELECT
        for op in [0x1D, 0x3B, 0x04, 0x2A, 0x15, 0x55] {
            assert!(matches!(check_cdb(&[op, 0, 0, 0, 0, 0]), Err(SgError::Forbidden(_))));
        }
        assert!(matches!(check_cdb(&[OP_LOG_SENSE, 0x01, 0x4D, 0, 0, 0, 0, 0, 0, 0]), Err(SgError::LogSenseSave)));
        assert!(check_cdb(&[]).is_err());
    }

    #[test]
    fn header_layout() {
        // Matches struct sg_io_hdr on x86_64.
        assert_eq!(std::mem::size_of::<SgIoHdr>(), 88);
    }
}
