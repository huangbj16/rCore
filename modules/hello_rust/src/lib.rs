#![no_std]
#![feature(alloc)]
#![feature(global_asm)]

extern crate rcore;
mod main;

global_asm!(r#"
    .section .rcore-lkm
    .incbin "lkm_info.txt"
"#);
