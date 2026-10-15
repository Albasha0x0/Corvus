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

#[no_mangle] #[inline(never)]
pub extern "C" fn leaf(x: i32) -> i32 { x * 3 + 7 }

#[no_mangle] #[inline(never)]
pub extern "C" fn middle(a: i32, b: i32) -> i32 { leaf(a) + leaf(b) }

#[no_mangle] #[inline(never)]
pub extern "C" fn classify(v: i32) -> i32 {
    match v { 0 => middle(v, 1) + 1, 1 => leaf(v) + 2, 2 => 11, 3 => 23, 4 => 31, 5 => 47, _ => 99 }
}

#[no_mangle]
pub extern "C" fn _start(x: i32) -> i32 { classify(middle(x, 3)) + 5 }
