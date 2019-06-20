use super::api::*;
use super::const_reloc as loader;
use super::kernelvm::*;
use super::structs::*;
use crate::consts::*;
use crate::lkm::structs::ModuleState::{Ready, Unloading};
use crate::memory::GlobalFrameAlloc;
use crate::sync::{Condvar, SpinLock as Mutex};
use crate::syscall::SysError::*;
use crate::syscall::SysResult;
use alloc::boxed::Box;
use alloc::collections::btree_map::BTreeMap;
use alloc::prelude::*;
use alloc::string::*;
use alloc::sync::Arc;
use alloc::vec::*;
use core::borrow::BorrowMut;
use core::mem::transmute;
use core::slice;
use lazy_static::lazy_static;
use rcore_memory::memory_set::handler::{ByFrame, MemoryHandler};
use rcore_memory::memory_set::MemoryAttr;
use rcore_memory::{Page, PAGE_SIZE};
use xmas_elf::dynamic::Tag;
use xmas_elf::program::Type::Load;
use xmas_elf::sections::SectionData;
use xmas_elf::sections::SectionData::{DynSymbolTable64, Dynamic64, Undefined};
use xmas_elf::symbol_table::DynEntry64;
use xmas_elf::symbol_table::Entry;
use xmas_elf::{
    header,
    program::{Flags, Type},
    ElfFile,
};
// The symbol data table.
global_asm!(include_str!("symbol_table.asm"));

/// `ModuleManager` is the core part of LKM.
/// It does these jobs:
/// - load preset(API) symbols
/// - manage module loading dependency and linking modules.
pub struct ModuleManager {
    stub_symbols: BTreeMap<String, ModuleSymbol>,
    loaded_modules: Vec<Box<LoadedModule>>,
}

lazy_static! {
    pub static ref LKM_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::new());
}

impl ModuleManager {
    /// Load kernel symbols from `rcore_symbol_table` label
    pub fn load_kernel_symbols(&mut self) {
        use compression::prelude::*;
        use core::str::from_utf8;

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
            return;
        }
        let zipped_symbols =
            unsafe { slice::from_raw_parts(symbol_table_start as *const u8, symbol_table_len) };

        let real_symbols = zipped_symbols
            .to_vec()
            .decode(&mut GZipDecoder::new())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let real_symbols_utf8 = unsafe { from_utf8(&real_symbols).unwrap() };

        self.add_kernel_symbols(parse_kernel_symbols(real_symbols_utf8));
    }

    pub fn add_kernel_symbols(&mut self, symbols: impl Iterator<Item = ModuleSymbol>) {
        for symbol in symbols {
            self.stub_symbols.insert(symbol.name.clone(), symbol);
        }
    }

    pub fn resolve_symbol(&self, symbol: &str) -> Option<usize> {
        self.find_symbol_in_deps(symbol, 0)
    }
    fn find_symbol_in_deps(&self, symbol: &str, this_module: usize) -> Option<usize> {
        if symbol == "THIS_MODULE" {
            return Some(this_module);
        }
        if let Some(sym) = self.stub_symbols.get(symbol) {
            return Some(sym.loc);
        }

        for km in self.loaded_modules.iter().rev() {
            for sym in km.exported_symbols.iter() {
                if (&sym.name) == symbol {
                    return Some(sym.loc);
                }
            }
        }
        None
    }

    fn find_module(&mut self, name: &str) -> Option<&mut Box<LoadedModule>> {
        self.loaded_modules.iter_mut().find(|m| m.info.name == name)
    }

    pub fn init_module(&mut self, module_image: &[u8], param_values: &str) -> SysResult {
        let elf = ElfFile::new(module_image).expect("[LKM] failed to read elf");

        // check 64 bit
        let is32 = match elf.header.pt2 {
            header::HeaderPt2::Header32(_) => true,
            header::HeaderPt2::Header64(_) => false,
        };
        if is32 {
            error!("[LKM] 32-bit elf is not supported!");
            return Err(ENOEXEC);
        }

        // check type
        match elf.header.pt2.type_().as_type() {
            header::Type::SharedObject => {}
            _ => {
                error!("[LKM] a kernel module must be some shared object!");
                return Err(ENOEXEC);
            }
        }

        // check and get LKM info
        let minfo = elf.module_info().map_err(|s| {
            error!("[LKM] {}", s);
            ENOEXEC
        })?;

        info!(
            "[LKM] loading module {} version {} api_version {}",
            minfo.name, minfo.version, minfo.api_version
        );

        // check name
        if self.find_module(&minfo.name).is_some() {
            error!(
                "[LKM] another instance of module {} (api version {}) has been loaded!",
                minfo.name, minfo.api_version
            );
            return Err(EEXIST);
        }

        // check dependencies
        for dependent in minfo.dependent_modules.iter() {
            let module = self.find_module(&dependent.name).ok_or_else(|| {
                error!("[LKM] dependent module not found: {}", dependent.name);
                ENOEXEC
            })?;
            if module.info.api_version != dependent.api_version {
                error!(
                    "[LKM] dependent module {} found but with a different api version {}!",
                    module.info.name, module.info.api_version
                );
                return Err(ENOEXEC);
            }
        }
        // increase reference count of dependent modules
        for dependent in minfo.dependent_modules.iter() {
            let module = self.find_module(&dependent.name).unwrap();
            module.used_counts += 1;
        }

        let map_len = elf.map_len();
        // We first map a huge piece. This requires the kernel model to be dense and not abusing vaddr.
        let mut vspace = { VirtualSpace::new(&KERNELVM_MANAGER, map_len) }.ok_or_else(|| {
            error!("[LKM] valloc failed!");
            ENOMEM
        })?;
        let base = vspace.start();

        //loaded_minfo.mem_start=base as usize;
        //loaded_minfo.mem_size=(map_len/PAGE_SIZE) as usize;
        //if map_len%PAGE_SIZE>0{
        //    loaded_minfo.mem_size+=1;
        //}
        for ph in elf.program_iter() {
            if ph.get_type().map_err(|_| {
                error!("[LKM] program header error!");
                ENOEXEC
            })? == Load
            {
                let vspace_ref = &mut vspace;
                let prog_start_addr = base + (ph.virtual_addr() as usize);
                let prog_end_addr = prog_start_addr + (ph.mem_size() as usize);
                let offset = ph.offset() as usize;
                let flags = ph.flags();
                let mut attr = MemoryAttr::default();
                if flags.is_write() {
                    attr = attr.writable();
                }
                if flags.is_execute() {
                    attr = attr.execute();
                }
                let area_ref = vspace_ref.add_area(prog_start_addr, prog_end_addr, &attr);
                //self.vallocator.map_pages(prog_start_addr, prog_end_addr, &attr);
                //No need to flush TLB.
                let target = unsafe {
                    ::core::slice::from_raw_parts_mut(
                        prog_start_addr as *mut u8,
                        ph.mem_size() as usize,
                    )
                };
                let file_size = ph.file_size() as usize;
                if file_size > 0 {
                    target[..file_size].copy_from_slice(&elf.input[offset..offset + file_size]);
                }
                target[file_size..].iter_mut().for_each(|x| *x = 0);
                //drop(vspace);
            }
        }

        let mut loaded_minfo = Box::new(LoadedModule {
            info: minfo,
            exported_symbols: Vec::new(),
            used_counts: 0,
            using_counts: Arc::new(ModuleRef {}),
            vspace,
            lock: Mutex::new(()),
            state: Ready,
        });
        info!(
            "[LKM] module load done at {}, now need to do the relocation job.",
            base
        );

        info!("[LKM] relocating three sections");
        let this_module = &(*loaded_minfo) as *const _ as usize;
        elf.relocate_symbols(
            base,
            |name| self.find_symbol_in_deps(name, this_module),
            |addr, value| unsafe {
                (addr as *mut usize).write(value);
            },
        )
        .map_err(|s| {
            error!("[LKM] {}", s);
            ENOEXEC
        })?;
        info!("[LKM] relocation done. adding module to manager and call init_module");
        let mut lkm_entry: usize = 0;
        for exported in loaded_minfo.info.exported_symbols.iter() {
            for sym in elf.dynsym().map_err(|s| {
                error!("[LKM] {}", s);
                ENOEXEC
            })? {
                if exported
                    == sym.get_name(&elf).map_err(|_| {
                        error!("[LKM] load symbol name error!");
                        ENOEXEC
                    })?
                {
                    let exported_symbol = ModuleSymbol {
                        name: exported.clone(),
                        loc: base + (sym.value() as usize),
                    };

                    if exported == "init_module" {
                        lkm_entry = base + (sym.value() as usize);
                    } else {
                        loaded_minfo.exported_symbols.push(exported_symbol);
                    }
                }
            }
        }
        // Now everything is done, and the entry can be safely plugged into the vector.
        self.loaded_modules.push(loaded_minfo);
        if lkm_entry == 0 {
            error!("[LKM] this module does not have init_module()!");
            return Err(ENOEXEC);
        }
        info!("[LKM] calling init_module at {}", lkm_entry);
        unsafe {
            LKM_MANAGER.force_unlock();
            let init_module: extern "C" fn() = transmute(lkm_entry);
            init_module();
        }
        Ok(0)
    }

    pub fn delete_module(&mut self, name: &str, flags: u32) -> SysResult {
        //unimplemented!("[LKM] You can't plug out what's INSIDE you, RIGHT?");

        info!("[LKM] now you can plug out a kernel module!");
        let module = self.find_module(name).ok_or(ENOENT)?;

        let mod_lock = module.lock.lock();
        if module.used_counts > 0 {
            error!("[LKM] some module depends on this module!");
            return Err(EAGAIN);
        }
        if Arc::strong_count(&module.using_counts) > 0 {
            error!("[LKM] there are references to the module!");
        }
        let mut cleanup_func: usize = 0;
        for entry in module.exported_symbols.iter() {
            if (&(entry.name)) == "cleanup_module" {
                cleanup_func = entry.loc;
                break;
            }
        }
        if cleanup_func > 0 {
            unsafe {
                module.state = Unloading;
                let cleanup_module: fn() = transmute(cleanup_func);
                (cleanup_module)();
            }
        } else {
            error!("[LKM] you cannot plug this module out.");
            return Err(EBUSY);
        }
        drop(mod_lock);

        // remove module
        self.loaded_modules.retain(|m| m.info.name != name);
        unsafe {
            LKM_MANAGER.force_unlock();
        }
        info!("[LKM] Remove module {:?} done!", name);
        Ok(0)
    }

    pub fn new() -> Self {
        info!("[LKM] Loadable Kernel Module Manager loading...");
        let mut kmm = ModuleManager {
            stub_symbols: BTreeMap::new(),
            loaded_modules: Vec::new(),
        };
        kmm.load_kernel_symbols();
        info!("[LKM] Loadable Kernel Module Manager loaded!");
        kmm
    }
}

/// Parse kernel symbols from 'nm kernel.elf' output string
pub fn parse_kernel_symbols<'a>(s: &'a str) -> impl Iterator<Item = ModuleSymbol> + 'a {
    s.lines().map(|l| {
        let mut words = l.split_whitespace();
        let address = words.next().unwrap();
        let stype = words.next().unwrap();
        let name = words.next().unwrap();
        ModuleSymbol {
            name: String::from(name),
            loc: usize::from_str_radix(address, 16).unwrap(),
        }
    })
}

/// Helper functions for ELF
trait ElfExt {
    /// Calculate length of LOAD sections to map
    fn map_len(&self) -> usize;

    /// Get dynamic entries from '.dynsym' section
    fn dynsym(&self) -> Result<&[DynEntry64], &'static str>;

    /// Parse LKM info from '.rcore-lkm' section
    fn module_info(&self) -> Result<ModuleInfo, &'static str>;

    /// Relocate all symbols.
    fn relocate_symbols(
        &self,
        base: usize,
        query_symbol_location: impl Fn(&str) -> Option<usize>,
        write_ptr: impl Fn(usize, usize),
    ) -> Result<(), &'static str>;
}

impl ElfExt for ElfFile<'_> {
    fn map_len(&self) -> usize {
        let mut max_addr: usize = 0;
        let mut min_addr: usize = ::core::usize::MAX;
        let mut off_start: usize = 0;
        for ph in self.program_iter() {
            if ph.get_type().unwrap() == Load {
                if (ph.virtual_addr() as usize) < min_addr {
                    min_addr = ph.virtual_addr() as usize;
                    off_start = ph.offset() as usize;
                }
                if (ph.virtual_addr() + ph.mem_size()) as usize > max_addr {
                    max_addr = (ph.virtual_addr() + ph.mem_size()) as usize;
                }
            }
        }
        fn page_align_down(addr: usize) -> usize {
            addr / PAGE_SIZE * PAGE_SIZE
        }
        fn page_align_up(addr: usize) -> usize {
            (addr + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
        }
        max_addr = page_align_up(max_addr);
        min_addr = page_align_down(min_addr);
        off_start = page_align_down(off_start);
        max_addr - min_addr + off_start
    }

    fn dynsym(&self) -> Result<&[DynEntry64], &'static str> {
        match self
            .find_section_by_name(".dynsym")
            .ok_or(".dynsym not found!")?
            .get_data(self)
            .map_err(|_| "corrupted .dynsym!")?
        {
            DynSymbolTable64(dsym) => Ok(dsym),
            _ => Err("bad .dynsym"),
        }
    }

    fn module_info(&self) -> Result<ModuleInfo, &'static str> {
        let info_content = match self
            .find_section_by_name(".rcore-lkm")
            .ok_or("rcore-lkm metadata not found!")?
            .get_data(self)
            .map_err(|_| "load rcore-lkm error!")?
        {
            Undefined(c) => core::str::from_utf8(c).map_err(|_| "info content is not utf8")?,
            _ => return Err("metadata section type wrong! this is not likely to happen..."),
        };
        let minfo = ModuleInfo::parse(info_content).ok_or("parse info error!")?;
        Ok(minfo)
    }

    fn relocate_symbols(
        &self,
        base: usize,
        query_symbol_location: impl Fn(&str) -> Option<usize>,
        write_ptr: impl Fn(usize, usize),
    ) -> Result<(), &'static str> {
        let dynsym = self.dynsym()?;

        // define a closure to relocate one symbol
        let relocate_symbol =
            |sti: usize, offset: usize, addend: usize, itype: usize| -> Result<(), &'static str> {
                if sti == 0 {
                    return Ok(());
                }
                let dynsym = &dynsym[sti];
                let sym_val = if dynsym.shndx() == 0 {
                    let name = dynsym.get_name(self)?;
                    query_symbol_location(name).ok_or("symbol not found")?
                } else {
                    base + dynsym.value() as usize
                };
                match itype as usize {
                    loader::REL_NONE => {}
                    loader::REL_OFFSET32 => panic!("[LKM] REL_OFFSET32 detected!"),
                    loader::REL_SYMBOLIC | loader::REL_GOT | loader::REL_PLT => {
                        write_ptr(base + offset, sym_val + addend);
                    }
                    loader::REL_RELATIVE => {
                        write_ptr(base + offset, base + addend);
                    }
                    _ => panic!("[LKM] unsupported relocation type: {}", itype),
                }
                Ok(())
            };

        // for each REL & RELA section ...
        for section in self.section_iter() {
            match section.get_data(self)? {
                SectionData::Rela64(rela_items) => {
                    for item in rela_items.iter() {
                        relocate_symbol(
                            item.get_symbol_table_index() as usize,
                            item.get_offset() as usize,
                            item.get_addend() as usize,
                            item.get_type() as usize,
                        )?;
                    }
                }
                SectionData::Rel64(rel_items) => {
                    for item in rel_items.iter() {
                        relocate_symbol(
                            item.get_symbol_table_index() as usize,
                            item.get_offset() as usize,
                            0,
                            item.get_type() as usize,
                        )?;
                    }
                }
                _ => continue,
            }
        }
        Ok(())
    }
}
