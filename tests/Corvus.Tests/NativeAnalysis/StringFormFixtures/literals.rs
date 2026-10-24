#![no_std]
#![no_main]

use core::hint::black_box;

// Takes each literal as a pointer and a length; rustc merges the literals into one run without terminators.
#[inline(never)]
fn show(s: &str) -> usize { black_box(s).len() }

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> usize {
    show("opening configuration") + show("config.toml") + show("connection refused") + show("retrying in 5 seconds")
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
