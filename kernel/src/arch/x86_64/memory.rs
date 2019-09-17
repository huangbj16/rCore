use super::paging::PageTableImpl;
use crate::memory::FRAME_ALLOCATOR;
use bitmap_allocator::BitAlloc;
use rboot::{BootInfo, MemoryType};
use rcore_memory::paging::*;
use rcore_memory::PAGE_SIZE;

pub fn init(boot_info: &BootInfo) {
    init_frame_allocator(boot_info);
    info!("memory: init end");
}

/// Init FrameAllocator and insert all 'Usable' regions from BootInfo.
fn init_frame_allocator(boot_info: &BootInfo) {
    let mut ba = FRAME_ALLOCATOR.lock();
    for region in boot_info.memory_map.clone().iter {
        if region.ty == MemoryType::CONVENTIONAL {
            let start_frame = region.phys_start as usize / PAGE_SIZE;
            let end_frame = start_frame + region.page_count as usize;
            ba.insert(start_frame..end_frame);
        }
    }
}
