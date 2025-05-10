pub use core::str::from_utf8_unchecked;

pub use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes},
    macros::{kprobe, map},
    maps::{HashMap, LruHashMap, PerfEventArray},
    programs::ProbeContext,
};
#[allow(unused_imports)]
pub use aya_log_ebpf::{debug, error, info};
pub use kspy_common::{WriteEvent, ZEROED_ARRAY_1024};

#[map]
pub static TARGET_PIDS: HashMap<i32, u8> = HashMap::with_max_entries(10, 0);
