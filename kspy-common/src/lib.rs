#![no_std]
pub const MAX_PATH_LEN: usize = 1024;

pub const ZEROED_ARRAY_1024: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct WriteEvent {
    pub pid: u64,
    pub path: [u8; MAX_PATH_LEN],
    pub count: usize,
    pub offset: i64,
}
