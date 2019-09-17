#![no_std]

extern crate alloc;

use alloc::alloc::GlobalAlloc;
use log::Log;

#[derive(Clone)]
pub struct RcoreAPI {
    /// Global allocator
    pub allocator: &'static dyn GlobalAlloc,
    /// Logger
    pub logger: &'static dyn Log,
    /// Just for test
    pub test: fn(),
}

unsafe impl Send for RcoreAPI {}
unsafe impl Sync for RcoreAPI {}
