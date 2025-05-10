#![no_std]
pub const MAX_PATH_LEN: usize = 1024;

pub const ZEROED_ARRAY_1024: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WriteEvent {
    pub pid: u32,
    pub inode: u64,
    pub dentry: u64,
    pub mnt: u64,
    pub count: u64,
    pub offset: u64,
    pub filename: [u8; MAX_PATH_LEN],
}

#[repr(C)]
pub struct OpenEvent {
    pub pid: u32,
    pub fd: i32,
    pub path: [u8; 256],
}
