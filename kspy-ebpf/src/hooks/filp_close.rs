#![allow(unused)]
use aya_ebpf::{macros::fentry, programs::FEntryContext};
use aya_log_ebpf::info;

use crate::{
    bindgen::{self, file},
    common::*,
};

#[fentry(function = "filp_close")]
pub fn ff(ctx: FEntryContext) -> u32 {
    match try_ff(&ctx) {
        Ok(_) => 0,
        Err(i) => {
            error!(&ctx, "Error: {}", i);
            i as u32
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Event {
    pub pid: u64,
    pub path: [u8; 1024],
}

const INIT_ENENT: Event = Event {
    pid: 0,
    path: [0; 1024],
};

#[map]
pub static TT: LruHashMap<u64, Event> = LruHashMap::with_max_entries(16, 0);

fn try_ff(ctx: &FEntryContext) -> Result<(), i64> {
    let file_ptr: *const file = unsafe { ctx.arg(0) };

    let addr = file_ptr as u64;
    TT.insert(&addr, &INIT_ENENT, 0).map_err(|_| -6)?;
    let event = unsafe { &mut *TT.get_ptr_mut(&addr).ok_or(-7)? };

    // let file_ptr = file_addr as *const file;
    let file_val = unsafe { bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)? };
    let path_ptr = file_val.f_path;

    unsafe {
        // failed
        // bpf_d_path(
        //     &mut path_ptr as *mut bindgen::path as *mut aya_ebpf::bindings::path,
        //     event.path.as_mut_ptr() as *mut i8,
        //     0,
        // );
        // info!(ctx, "bpf_d_path");
    };

    info!(ctx, "function filp_close called");
    Ok(())
}
