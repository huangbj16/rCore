#![no_std]
#![no_main]
#![feature(global_asm)]

use rcore_module;

global_asm!(
    r#"
    .section .rcore-lkm
    .incbin "lkm_info.txt"
"#
);
