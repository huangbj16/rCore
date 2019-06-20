use self::kernelvm::ProviderImpl;
use alloc::string::String;
use alloc::vec::Vec;
use compression::prelude::*;
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
        let real_symbols = load_kernel_symbols_str();
        let kernel_symbols = parse_kernel_symbols(unsafe { from_utf8(&real_symbols).unwrap() });
        kmm.add_kernel_symbols(kernel_symbols);
        Mutex::new(kmm)
    };
}

// The symbol data table.
global_asm!(include_str!("symbol_table.asm"));

/// Load content from `rcore_symbol_table` label
fn load_kernel_symbols_str() -> Vec<u8> {
    extern "C" {
        fn rcore_symbol_table();
        static rcore_symbol_table_size: usize;
    }
    let symbol_table_start = rcore_symbol_table as usize;
    let symbol_table_len = unsafe { rcore_symbol_table_size };
    info!(
        "Loading kernel symbol table {:08x} with size {:08x}",
        symbol_table_start, symbol_table_len
    );
    if symbol_table_len == 0 {
        warn!("Load kernel symbol table failed! This is because you didn't attach kernel table onto binary.");
        return Vec::new();
    }
    let zipped_symbols =
        unsafe { core::slice::from_raw_parts(symbol_table_start as *const u8, symbol_table_len) };
    zipped_symbols
        .to_vec()
        .decode(&mut GZipDecoder::new())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

/// Parse kernel symbols from 'nm kernel.elf' output string
pub fn parse_kernel_symbols<'a>(s: &'a str) -> impl Iterator<Item = ModuleSymbol> + 'a {
    s.lines().map(|l| {
        let mut words = l.split_whitespace();
        let address = words.next().unwrap();
        let _stype = words.next().unwrap();
        let name = words.next().unwrap();
        ModuleSymbol {
            name: String::from(name),
            loc: usize::from_str_radix(address, 16).unwrap(),
        }
    })
}
