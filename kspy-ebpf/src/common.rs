pub use core::str::from_utf8_unchecked;

pub use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{kprobe, map},
    maps::LruHashMap,
    programs::ProbeContext,
};
pub use aya_log_ebpf::info;
pub use kspy_common::MAX_PATH_LEN;
#[repr(C)]
pub struct WriteEvent {
    pub pid: u64,
    pub path: [u8; MAX_PATH_LEN],
    pub count: usize,
}

pub const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[map]
pub static WRITE_ENENTS: LruHashMap<u64, WriteEvent> = LruHashMap::with_max_entries(16, 0);
