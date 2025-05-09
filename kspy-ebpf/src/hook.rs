use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::{
    bindgen::{dentry, file},
    common::*,
};

#[kprobe]
pub fn hook_vfs_write(ctx: ProbeContext) -> u32 {
    match { try_vfs_write(&ctx) } {
        Ok(_) => 0,
        Err(i) => {
            error!(&ctx, "Error: {}", i);
            i as u32
        }
    }
}

const INIT_ENENT: WriteEvent = WriteEvent {
    pid: 0,
    path: ZEROED_ARRAY,
    count: 0,
};

// 参数：struct file *file, const char __user *buf, size_t count, loff_t *pos
fn try_vfs_write(ctx: &ProbeContext) -> Result<(), i64> {
    let file_addr = ctx.arg::<u64>(0).ok_or(-5)?;
    let file_ptr = file_addr as *const file;
    WRITE_ENENTS
        .insert(&file_addr, &INIT_ENENT, 0)
        .map_err(|_| -6)?;
    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&file_addr).ok_or(-7)? };
    let pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    unsafe {
        let file_val = bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)?;
        let dentry_ptr = file_val.f_path.dentry;
        let dentry_val = bpf_probe_read_kernel::<dentry>(dentry_ptr).map_err(|_| -9)?;
        let name_ptr = dentry_val.d_name.name;
        bpf_probe_read_user_str_bytes(name_ptr, &mut event.path).map_err(|_| -10)?;
    };
    let xfname = unsafe { from_utf8_unchecked(&event.path) };
    info!(ctx, "vfs_write: file: {}", xfname);
    info!(ctx, "vfs_write: file: {}", file_ptr as u64);
    Ok(())
}
