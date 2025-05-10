use crate::{
    bindgen::{self, file},
    common::*,
};

#[kprobe]
pub fn push_hook_info(ctx: ProbeContext) -> u32 {
    match { try_push_hook_info(&ctx) } {
        Ok(_) => 0,
        Err(i) => {
            error!(&ctx, "Error: {}", i);
            i as u32
        }
    }
}

// params：struct file *file, const char __user *buf, size_t count, loff_t *pos
fn try_push_hook_info(ctx: &ProbeContext) -> Result<(), i64> {
    let file_addr = ctx.arg::<u64>(0).ok_or(-10)?;
    let file_ptr = file_addr as *const file;
    let file_val = unsafe { bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)? };
    let mut path_ptr = file_val.f_path;

    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&file_addr).ok_or(-12)? };

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.count = ctx.arg::<u64>(2).ok_or(-13)? as usize;
    event.offset = ctx.arg::<u64>(3).ok_or(-14)? as i64;

    unsafe {
        bpf_d_path(
            &mut path_ptr as *mut bindgen::path as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut i8,
            0,
        );
        info!(ctx, "bpf_d_path");
    };
    #[allow(static_mut_refs)]
    unsafe {
        PERF_ARRAY.output(ctx, &event, 0);
    }
    Ok(())
}
