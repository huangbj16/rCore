use self::kernelvm::ProviderImpl;
use alloc::string::String;
use alloc::vec::Vec;
use core::str::from_utf8;
use lazy_static::lazy_static;
use rcore_lkm::manager::ModuleManager;
use rcore_lkm::structs::ModuleSymbol;
use spin::Mutex;

pub mod api;
pub mod kernelvm;

lazy_static! {
    pub static ref LKM_MANAGER: Mutex<ModuleManager> = {
        let mut kmm = ModuleManager::new(ProviderImpl::default());
        Mutex::new(kmm)
    };
}
