pub use core::str::from_utf8_unchecked;

pub use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, map},
    maps::{HashMap, LruHashMap, PerfEventArray, ProgramArray},
    programs::ProbeContext,
};
#[allow(unused_imports)]
pub use aya_log_ebpf::{debug, error, info};
pub use kspy_common::{WriteEvent, ZEROED_ARRAY_1024};

#[map]
pub static WRITE_ENENTS: LruHashMap<u64, WriteEvent> = LruHashMap::with_max_entries(16, 0);

#[map]
pub static mut PERF_VFS_WRITE: PerfEventArray<WriteEvent> = PerfEventArray::new(0);

#[map]
pub static TARGET_PIDS: HashMap<i32, u8> = HashMap::with_max_entries(10, 0);

#[map]
pub static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(1, 0);

#[inline(always)]
pub fn try_tail_call(ctx: &ProbeContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call failed");
    }
}
