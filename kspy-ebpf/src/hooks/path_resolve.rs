use core::ffi::c_void;

use aya_ebpf::helpers::r#gen;

use crate::{
    bindgen::{dentry, file, qstr},
    common::*,
};

#[kprobe]
pub fn hook_path_reso(ctx: ProbeContext) -> u32 {
    match { try_path_reso(&ctx) } {
        Ok(_) => 0,
        Err(i) => {
            error!(&ctx, "Error: {}", i);
            i as u32
        }
    }
}

// params：struct file *file, const char __user *buf, size_t count, loff_t *pos
#[inline(always)]
fn try_path_reso(ctx: &ProbeContext) -> Result<(), i64> {
    let file_addr = ctx.arg::<u64>(0).ok_or(-5)?;
    let file_ptr = file_addr as *const file;

    let event = unsafe { &mut *WRITE_ENENTS.get_ptr_mut(&file_addr).ok_or(-7)? };

    unsafe {
        let file_val = bpf_probe_read_kernel::<file>(file_ptr).map_err(|_| -8)?;
        let dentry_ptr = file_val.f_path.dentry;
        extract_path(dentry_ptr, &mut event.path);
    }

    debug!(ctx, "Path: {}", unsafe { from_utf8_unchecked(&event.path) });

    #[allow(static_mut_refs)]
    unsafe {
        PERF_VFS_WRITE.output(ctx, &event, 0);
    }

    Ok(())
}

const MAX_PATH_DEPTH: usize = 6; // 防止 verifier 不通过

impl qstr {
    #[inline(always)]
    pub fn safe_len(&self) -> usize {
        unsafe { self.__bindgen_anon_1.__bindgen_anon_1.len as usize }
    }
}

const MAX_NAME_LEN: usize = 128;
const MAX_PATH_LEN: usize = 1024;

pub unsafe fn extract_path(mut dentry_ptr: *const dentry, path_buf: &mut [u8; MAX_PATH_LEN]) {
    let mut offset = 0;

    for _ in 0..MAX_PATH_DEPTH {
        if dentry_ptr.is_null() || offset >= path_buf.len() {
            break;
        }

        let dentry_val = match bpf_probe_read_kernel::<dentry>(dentry_ptr) {
            Ok(val) => val,
            Err(_) => break,
        };

        let name_ptr = dentry_val.d_name.name;

        let raw_len = dentry_val.d_name.safe_len();
        let name_len = core::cmp::min((raw_len as usize) & 0x3F, MAX_NAME_LEN - 1);
        let dst = path_buf.as_mut_ptr().add(offset);
        offset += name_len + 1;

        gen::bpf_probe_read(
            dst as *mut c_void,
            name_len as u32,
            name_ptr as *const c_void,
        );
        path_buf[offset - 1] = b'/';

        dentry_ptr = dentry_val.d_parent;
    }

    if offset == 0 {
        path_buf[offset] = b'/';
        path_buf[offset + 1] = 0;
    }
}
