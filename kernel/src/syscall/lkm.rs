use crate::lkm::LKM_MANAGER;
use crate::sync::Mutex;
use crate::syscall::{check_and_clone_cstr, SysResult, Syscall};
use alloc::collections::btree_map::BTreeMap;

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
            .init_module(modimg, &copied_param_values)
            .map_err(|x| unsafe { core::mem::transmute(x) })
    }

    pub fn sys_delete_module(&mut self, module_name: *const u8, flags: u32) -> SysResult {
        let mut proc = self.process();
        let copied_modname = check_and_clone_cstr(module_name)?;

        LKM_MANAGER
            .lock()
            .delete_module(&copied_modname, flags)
            .map_err(|x| unsafe { core::mem::transmute(x) })
    }
}
