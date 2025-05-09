use crate::{bindgen::file, common::*};

#[kprobe]
pub fn vfs_write(ctx: ProbeContext) -> u32 {
    match { try_vfs_write(ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

const INIT_ENENT: WriteEvent = WriteEvent {
    pid: 0,
    path: ZEROED_ARRAY,
    count: 0,
};

// 参数：struct file *file, const char __user *buf, size_t count, loff_t *pos
fn try_vfs_write(ctx: ProbeContext) -> Result<(), i64> {
    let file = ctx.arg::<*const file>(0).unwrap();
    WRITE_ENENTS.insert(&(file as u64), &INIT_ENENT, 0)?;
    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&(file as u64)).ok_or(-1)? };
    let pid = bpf_get_current_pid_tgid() >> 32;

    event.pid = pid;
    unsafe {
        let dentry = (*file).f_path.dentry;
        let name_ptr = (*dentry).d_name.name;
        bpf_probe_read_user_str_bytes(name_ptr, &mut event.path)
    }?;

    let xfname = unsafe { from_utf8_unchecked(&event.path) };
    info!(&ctx, "vfs_write: file: {}", xfname);
    Ok(())
}
