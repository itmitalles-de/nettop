//! Linux per-thread capability handling for the optional capture helper.
//!
//! The UI has no file capabilities. The helper receives only NET_RAW,
//! DAC_READ_SEARCH and SYS_PTRACE. After opening pcap, its worker drops all
//! capabilities; the sampling thread keeps only the two /proc read capabilities.

use anyhow::{Context, Result, bail};

const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_PTRACE: u32 = 19;
const READ_CAPS: u64 = (1 << CAP_DAC_READ_SEARCH) | (1 << CAP_SYS_PTRACE);
const REQUIRED_CAPS: u64 = READ_CAPS | (1 << CAP_NET_RAW);

#[repr(C)]
struct Header {
    version: u32,
    pid: i32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn permitted() -> Result<u64> {
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // The kernel capability ABI version 3 uses exactly two 32-bit words.
    let status = unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("reading thread capabilities");
    }
    Ok(u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32))
}

pub fn require_helper_capabilities() -> Result<()> {
    if permitted()? & REQUIRED_CAPS != REQUIRED_CAPS {
        bail!("Capture setup incomplete: run scripts/setup-capture.sh once as your regular user");
    }
    Ok(())
}

fn retain(allowed: u64) -> Result<()> {
    let keep = permitted()? & allowed;
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        Data {
            effective: keep as u32,
            permitted: keep as u32,
            inheritable: 0,
        },
        Data {
            effective: (keep >> 32) as u32,
            permitted: (keep >> 32) as u32,
            inheritable: 0,
        },
    ];
    let status = unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) };
    if status != 0 {
        return Err(std::io::Error::last_os_error()).context("dropping thread capabilities");
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).context("locking thread privileges");
    }
    Ok(())
}

/// Called by the capture worker itself, after opening its packet socket.
pub fn drop_capture_privileges() -> Result<()> {
    retain(0)
}

/// Called by the helper's sampling thread after the capture worker is ready.
pub fn retain_process_read_privileges() -> Result<()> {
    retain(READ_CAPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_thread_drops_all_capabilities_without_changing_parent() {
        let before = permitted().unwrap();
        std::thread::spawn(|| {
            drop_capture_privileges().unwrap();
            assert_eq!(permitted().unwrap(), 0);
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) },
                1
            );
        })
        .join()
        .unwrap();
        assert_eq!(permitted().unwrap(), before);
    }
}
