#![no_std]
#![no_main]

mod common;
mod hook;

// aya-tool generate file > vmlinux.rs
// replace `gen` -> `gen_`
#[allow(
    clippy::all,
    non_camel_case_types,
    non_upper_case_globals,
    non_snake_case,
    dead_code,
    missing_docs,
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::unnecessary_transmute
)]
mod bindgen {
    include!("vmlinux.rs");
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
