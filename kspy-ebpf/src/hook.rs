use crate::{
    bindgen::{self, dentry, file},
    common::*,
};

#[fentry(function = "vfs_write")]
pub fn hook_vfs_write(ctx: FEntryContext) -> u32 {
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
    path: ZEROED_ARRAY_1024,
    count: 0,
    offset: 0,
};

// params：struct file *file, const char __user *buf, size_t count, loff_t *pos
fn try_vfs_write(ctx: &FEntryContext) -> Result<(), i64> {
    // let file_addr = ctx.arg::<u64>(0).ok_or(-5)?;
    let file_addr: u64 = unsafe { ctx.arg(0) };
    let file_ptr = file_addr as *const file;
    WRITE_ENENTS
        .insert(&file_addr, &INIT_ENENT, 0)
        .map_err(|_| -6)?;
    let file_val = unsafe { bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)? };
    let mut path_ptr = file_val.f_path;
    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&file_addr).ok_or(-7)? };

    unsafe {
        let dentry_ptr = file_val.f_path.dentry;
        let dentry_val = bpf_probe_read_kernel::<dentry>(dentry_ptr).map_err(|_| -9)?;
        let name_ptr = dentry_val.d_name.name;

        let inode_ptr = file_val.f_inode;
        if inode_ptr.is_null() {
            return Ok(()); // 没有 inode，跳过
        }

        let i_mode = bpf_probe_read_kernel::<u16>(&((*inode_ptr).i_mode)).map_err(|_| -12)?;

        const S_IFMT: u16 = 0o170000;
        const S_IFREG: u16 = 0o100000;

        if (i_mode & S_IFMT) != S_IFREG {
            return Ok(()); // 跳过非普通文件
        }

        bpf_probe_read_kernel_str_bytes(name_ptr, &mut event.path).map_err(|_| -10)?;
    };
    let xfname = unsafe { from_utf8_unchecked(&event.path) };
    debug!(ctx, "vfs_write: filename: {}", xfname);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    // event.count = ctx.arg::<u64>(2).ok_or(-13)? as usize;
    event.count = unsafe { ctx.arg(2) };
    event.offset = unsafe { ctx.arg(3) };

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
