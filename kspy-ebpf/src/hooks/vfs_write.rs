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
    inode: 0,
    dentry: 0,
    mnt: 0,
    count: 0,
    offset: 0,
    filename: ZEROED_ARRAY_1024,
};

#[map]
static WRITE_ENENTS: LruHashMap<u64, WriteEvent> = LruHashMap::with_max_entries(16, 0);

#[map]
static mut PERF_VFS_WRITE: PerfEventArray<WriteEvent> = PerfEventArray::new(0);

// params：struct file *file, const char __user *buf, size_t count, loff_t *pos
fn try_vfs_write(ctx: &ProbeContext) -> Result<(), i64> {
    let pid = bpf_get_current_pid_tgid() as i32;
    unsafe {
        // not trace all PIDs and current PID is not in the target PIDs
        if TARGET_PIDS.get(&i32::MIN).is_none() && TARGET_PIDS.get(&pid).is_none() {
            debug!(ctx, "PID {} not in target PIDs", pid);
            return Ok(());
        }
    }

    let file_addr = ctx.arg::<u64>(0).ok_or(-5)?;
    let file_ptr = file_addr as *const file;
    WRITE_ENENTS
        .insert(&file_addr, &INIT_ENENT, 0)
        .map_err(|_| -6)?;
    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&file_addr).ok_or(-7)? };

    unsafe {
        let file_val = bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)?;
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

        bpf_probe_read_kernel_str_bytes(name_ptr, &mut event.filename).map_err(|_| -10)?;

        let inode_ptr = file_val.f_inode;
        let mnt_ptr = file_val.f_path.mnt;
        let inode_nr = bpf_probe_read_kernel(&(*inode_ptr).i_ino).map_err(|_| -9)?;
        event.pid = pid;
        event.inode = inode_nr;
        event.dentry = dentry_ptr as u64;
        event.mnt = mnt_ptr as u64;
        event.count = ctx.arg::<u64>(2).ok_or(-13)? as u64;
        event.offset = ctx.arg::<u64>(3).ok_or(-14)? as u64;
    };

    let xfname = unsafe { from_utf8_unchecked(&event.filename) };
    debug!(ctx, "vfs_write: filename: {}", xfname);

    #[allow(static_mut_refs)]
    unsafe {
        PERF_VFS_WRITE.output(ctx, &event, 0);
    }

    Ok(())
}
