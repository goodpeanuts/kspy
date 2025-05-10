pub use core::str::from_utf8_unchecked;

use aya_ebpf::maps::{PerfEventArray, ProgramArray};
pub use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, map},
    maps::LruHashMap,
    programs::ProbeContext,
};
#[allow(unused_imports)]
pub use aya_log_ebpf::{debug, error, info};
pub use kspy_common::{WriteEvent, ZEROED_ARRAY_1024};

#[map]
pub static WRITE_ENENTS: LruHashMap<u64, WriteEvent> = LruHashMap::with_max_entries(16, 0);

#[map]
pub static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[map]
pub static mut PERF_ARRAY: PerfEventArray<WriteEvent> = PerfEventArray::new(0);

#[inline(always)]
pub fn try_tail_call(ctx: &ProbeContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call {} failed", index);
    }
}
