use super::*;
use crate::lkm::LKM_MANAGER;
use crate::sync::Mutex;
use alloc::collections::btree_map::BTreeMap;
use rcore_lkm::manager::Error as LKMError;
use rcore_api::RcoreAPI;
use core::alloc::GlobalAlloc;
use log::Log;

impl Syscall<'_> {
    pub fn sys_init_module(
        &mut self,
        module_image: *const u8,
        len: usize,
        param_values: *const u8,
    ) -> SysResult {
        let mut proc = self.process();
        let modimg = unsafe { self.vm().check_read_array(module_image, len)? };
        let copied_param_values = check_and_clone_cstr(param_values)?;

        LKM_MANAGER
            .lock()
            .init_module(modimg, &copied_param_values, &*RCORE_API as *const _ as usize)?;
        Ok(0)
    }

    pub fn sys_delete_module(&mut self, module_name: *const u8, flags: u32) -> SysResult {
        let mut proc = self.process();
        let copied_modname = check_and_clone_cstr(module_name)?;

        LKM_MANAGER.lock().delete_module(&copied_modname, flags)?;
        Ok(0)
    }
}

impl From<LKMError> for SysError {
    fn from(e: LKMError) -> Self {
        error!("[LKM] {}", e.reason);
        unsafe { core::mem::transmute(e.kind as usize) }
    }
}

lazy_static! {
    static ref RCORE_API: RcoreAPI = RcoreAPI {
        allocator: &crate::HEAP_ALLOCATOR,
        logger: log::logger(),
        test: || info!("hello from kernel module"),
    };
}
