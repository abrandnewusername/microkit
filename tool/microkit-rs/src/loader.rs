use crate::{ElfFile, MemoryRegion};
use crate::util::{round_up, mb, kb, mask};
use crate::elf::ElfWordSize;
use std::path::Path;

const PAGE_TABLE_SIZE: usize = 4096;

const AARCH64_1GB_BLOCK_BITS: u64 = 30;
const AARCH64_2MB_BLOCK_BITS: u64 = 21;

const AARCH64_LVL0_BITS: u64 = 9;
const AARCH64_LVL1_BITS: u64 = 9;
const AARCH64_LVL2_BITS: u64 = 9;

struct Aarch64;
impl Aarch64 {
    pub fn lvl0_index(addr: u64) -> u64 {
        ((addr) >> (AARCH64_2MB_BLOCK_BITS + AARCH64_LVL2_BITS + AARCH64_LVL1_BITS)) & mask(AARCH64_LVL0_BITS)
    }
}

#[repr(C)]
struct LoaderRegion64 {
    load_addr: u64,
    size: u64,
    offset: u64,
    r#type: u64,
}

#[repr(C)]
struct LoaderData64 {
    magic: u64,
    flags: u64,
    kernel_entry: u64,
    ui_p_reg_start: u64,
    ui_p_reg_end: u64,
    pv_offset: u64,
    v_entry: u64,
    extra_device_addr_p: u64,
    extra_device_size: u64,
    num_regions: u64,
    regions: [LoaderRegion64],
}

struct Loader {
    magic: u64,
}

// TODO: why do we have optionals here?
impl Loader {
    pub fn new(loader_elf_path: &Path,
               kernel_elf: &ElfFile,
               initial_task_elf: &ElfFile,
               initial_task_phys_base: Option<u64>,
               reserved_region: MemoryRegion,
               system_regions: Vec<(u64, &[u8])>) -> Loader {
        // Note: If initial_task_phys_base is not None, then it just this address
        // as the base physical address of the initial task, rather than the address
        // that comes from the initial_task_elf file.
        let elf = match ElfFile::from_path(loader_elf_path) {
            Ok(e) => e,
            Err(err) => panic!("Could not load loader ELF with path '{:?}': {}", loader_elf_path, err),
        };
        let sz = elf.word_size;
        let magic = match sz {
            ElfWordSize::ThirtyTwo => 0x5e14dead,
            ElfWordSize::SixtyFour => 0x5e14dead14de5ead,
        };

        let mut regions = Vec::new();

        let mut kernel_first_vaddr = None;
        let mut kernel_last_vaddr = None;
        let mut kernel_first_paddr = None;
        let mut kernel_p_v_offset = None;

        for segment in &kernel_elf.segments {
            if segment.loadable {
                if kernel_first_vaddr.is_none() || segment.virt_addr < kernel_first_vaddr.unwrap() {
                    kernel_first_vaddr = Some(segment.virt_addr);
                }

                if kernel_last_vaddr.is_none() || segment.virt_addr + segment.mem_size() > kernel_last_vaddr.unwrap() {
                    kernel_last_vaddr = Some(round_up(segment.virt_addr + segment.mem_size(), mb(2)));
                }

                if kernel_first_paddr.is_none() || segment.phys_addr < kernel_first_paddr.unwrap() {
                    kernel_first_paddr = Some(segment.phys_addr);
                }

                if kernel_p_v_offset.is_none() {
                    kernel_p_v_offset = Some(segment.virt_addr - segment.phys_addr);
                } else if kernel_p_v_offset.unwrap() != segment.virt_addr - segment.phys_addr {
                    panic!("Kernel does not have a consistent physical to virtual offset");
                }

                regions.push((segment.phys_addr, &segment.data));
            }
        }

        assert!(kernel_first_paddr.is_some());

        // Note: This could be extended to support multi-segment ELF files
        // (and indeed initial did support multi-segment ELF files). However
        // it adds significant complexity, and the calling functions enforce
        // only single-segment ELF files, so we keep things simple here.
        assert!(initial_task_elf.segments.len() == 1);
        let segment = &initial_task_elf.segments[0];
        assert!(segment.loadable);

        let inittask_first_vaddr = segment.virt_addr;
        let inittask_last_vaddr = round_up(segment.virt_addr + segment.mem_size(), kb(4));

        let inittask_first_paddr = match initial_task_phys_base {
            Some(paddr) => paddr,
            None => segment.phys_addr,
        };
        let inittask_p_v_offset = inittask_first_vaddr - inittask_first_paddr;

        // Note: For now we include any zeroes. We could optimize in the future
        regions.push((inittask_first_paddr, &segment.data));

        // Determine the pagetable variables
        assert!(kernel_first_vaddr.is_some());
        assert!(kernel_first_vaddr.is_some());
        let pagetable_vars = Loader::setup_pagetables(&elf, kernel_first_vaddr.unwrap(), kernel_first_paddr.unwrap());

        let mut image_segment = elf.segments.into_iter().find(|segment| segment.loadable).expect("Did not find loadable segment");
        let image = &mut image_segment.data;

        if image_segment.virt_addr != elf.entry {
            panic!("The loader entry point must be the first byte in the image");
        }

        for (var_addr, var_size, var_data) in pagetable_vars {
            let offset = var_addr - image_segment.virt_addr;
            assert!(var_size == var_data.len() as u64);
            assert!(offset > 0);
            assert!(offset <= image.len() as u64);
            image[offset as usize..(offset + var_size) as usize].copy_from_slice(&var_data);
        }

        let kernel_entry = kernel_elf.entry;

        // TODO: don't we already have inittask_p_v_offset? I'm confused
        let pv_offset = inittask_first_paddr - inittask_first_vaddr;

        let ui_p_reg_start = inittask_first_paddr;
        let ui_p_reg_end = inittask_last_vaddr - inittask_p_v_offset;
        assert!(ui_p_reg_end > ui_p_reg_start);

        let v_entry = initial_task_elf.entry;

        let extra_device_addr_p = reserved_region.base;
        let extra_device_size = reserved_region.size();

        // let all_regions = [regions, system_regions].concat();

        Loader {
            magic,
        }
    }

    fn setup_pagetables(elf: &ElfFile, first_vaddr: u64, first_paddr: u64) -> [(u64, u64, [u8; PAGE_TABLE_SIZE]); 1] {
        let (boot_lvl1_lower_addr, boot_lvl1_lower_size) = elf.find_symbol("boot_lvl1_lower");
        let (boot_lvl1_upper_addr, _) = elf.find_symbol("boot_lvl1_upper");
        let (boot_lvl2_upper_addr, _) = elf.find_symbol("boot_lvl2_upper");

        let mut boot_lvl0_lower: [u8; PAGE_TABLE_SIZE] = [0; PAGE_TABLE_SIZE];
        boot_lvl0_lower[..8].copy_from_slice(&(boot_lvl1_lower_addr | 3).to_le_bytes());

        let mut boot_lvl1_lower: [u8; PAGE_TABLE_SIZE] = [0; PAGE_TABLE_SIZE];
        for i in 0..512 {
            let pt_entry: u64 =
                (i << AARCH64_1GB_BLOCK_BITS) |
                (1 << 10) | // access flag
                (0 << 2) | // strongly ordered memory
                (1); // 1G block
            let start = 8 * i as usize;
            let end = 8 * (i as usize + 1);
            boot_lvl1_lower[start..end].copy_from_slice(&pt_entry.to_le_bytes());
        }

        let mut boot_lvl0_upper: [u8; PAGE_TABLE_SIZE] = [0; PAGE_TABLE_SIZE];
        let pt_entry = boot_lvl1_upper_addr | 3;
        let idx = Aarch64::lvl0_index(first_vaddr);

        [
            (boot_lvl1_lower_addr, boot_lvl1_lower_size, boot_lvl0_lower),
            // ("boot_lvl1_lower", boot_lvl1_lower),
            // ("boot_lvl0_upper", boot_lvl0_upper),
            // ("boot_lvl1_upper", boot_lvl1_upper),
            // ("boot_lvl2_upper", boot_lvl2_upper),
        ]
    }
}
