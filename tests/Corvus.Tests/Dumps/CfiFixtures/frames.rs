#![no_core]
#![no_std]
#![feature(no_core, lang_items)]
#![allow(internal_features)]
#![crate_type = "lib"]

#[lang = "pointee_sized"] pub trait PointeeSized {}
#[lang = "meta_sized"] pub trait MetaSized: PointeeSized {}
#[lang = "sized"] pub trait Sized: MetaSized {}
#[lang = "copy"] pub trait Copy {}
impl Copy for i32 {}
#[lang = "add"] pub trait Add<Rhs = Self> { type Output; fn add(self, rhs: Rhs) -> Self::Output; }
impl Add for i32 { type Output = i32; fn add(self, rhs: i32) -> i32 { self + rhs } }
#[lang = "mul"] pub trait Mul<Rhs = Self> { type Output; fn mul(self, rhs: Rhs) -> Self::Output; }
impl Mul for i32 { type Output = i32; fn mul(self, rhs: i32) -> i32 { self * rhs } }

extern "C" { fn sink(p: *mut i32, n: i32) -> i32; }

// a frame with locals, callee-saved registers live across calls, and the return address saved
#[no_mangle] #[inline(never)]
pub extern "C" fn frame(n: i32) -> i32 {
    let mut buf = [0i32; 64];
    let a = unsafe { sink(&mut buf as *mut [i32; 64] as *mut i32, n) };
    let b = unsafe { sink(&mut buf as *mut [i32; 64] as *mut i32, a) };
    a * 3 + b + n
}

#[no_mangle] #[inline(never)]
pub extern "C" fn outer(n: i32) -> i32 { frame(n) * 2 + frame(n + 1) }

#[no_mangle] #[inline(never)]
pub extern "C" fn leaf(x: i32) -> i32 { x * 3 + 7 }
