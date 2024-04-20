mod sysxml;
mod util;
mod elf;

use std::fs;
use std::path::{Path, PathBuf};
use sysxml::{parse, SystemDescription};
use elf::ElfFile;

const INPUT_CAP_IDX: usize = 1;
const FAULT_EP_CAP_IDX: usize = 2;
const VSPACE_CAP_IDX: usize = 3;
const REPLY_CAP_IDX: usize = 4;
const MONITOR_EP_CAP_IDX: usize = 5;
const BASE_OUTPUT_NOTIFICATION_CAP: usize = 10;
const BASE_OUTPUT_ENDPOINT_CAP: usize = BASE_OUTPUT_NOTIFICATION_CAP + 64;
const BASE_IRQ_CAP: usize = BASE_OUTPUT_ENDPOINT_CAP + 64;
const MAX_SYSTEM_INVOCATION_SIZE: usize = util::mb(128);
const PD_CAPTABLE_BITS: usize = 12;
const PD_CAP_SIZE: usize = 256;
const PD_CAP_BITS: usize = PD_CAP_SIZE.ilog2() as usize;
const PD_SCHEDCONTEXT_SIZE: usize = 1 << 8;

#[derive(Copy, Clone)]
struct MemoryRegion {
    base: u64,
    end: u64,
}

impl MemoryRegion {
    pub fn new(base: u64, end: u64) -> MemoryRegion {
        MemoryRegion { base, end }
    }

    pub fn size(&self) -> u64 {
        self.end - self.base
    }
}

struct KernelConfig {
    word_size: usize,
    minimum_page_size: usize,
    paddr_user_device_top: usize,
    kernel_frame_size: usize,
    init_cnode_bits: usize,
    cap_address_bits: usize,
    fan_out_limit: usize,
}

struct BuiltSystem {
    // number_of_system_caps: int
    // invocation_data_size: int
    // bootstrap_invocations: List[Sel4Invocation]
    // system_invocations: List[Sel4Invocation]
    // kernel_boot_info: KernelBootInfo
    // reserved_region: MemoryRegion
    // fault_ep_cap_address: int
    // reply_cap_address: int
    // cap_lookup: Dict[int, str]
    // tcb_caps: List[int]
    // sched_caps: List[int]
    // ntfn_caps: List[int]
    // regions: List[Region]
    // kernel_objects: List[KernelObject]
    // initial_task_virt_region: MemoryRegion
    // initial_task_phys_region: MemoryRegion
}

fn phys_mem_regions_from_elf(elf: ElfFile, alignment: usize) -> Vec<MemoryRegion> {
    assert!(alignment > 0);

    elf.segments.into_iter().map(|s| MemoryRegion::new(
        util::round_down(s.phys_addr, alignment as u64),
        util::round_up(s.phys_addr + s.data.len() as u64, alignment as u64),
    )).collect()
}

fn phys_mem_region_from_elf(elf: ElfFile, alignment: usize) -> MemoryRegion {
    assert!(alignment > 0);
    assert!(elf.segments.len() == 1);

    phys_mem_regions_from_elf(elf, alignment)[0]
}

fn get_full_path(path: &Path, search_paths: &Vec<&str>) -> Option<PathBuf> {
    for search_path in search_paths {
        let full_path = Path::new(search_path).join(path);
        // TODO: use try_exists instead?
        if  full_path.exists() {
            return Some(full_path.to_path_buf());
        }
    }

    None
}

fn build_system(kernel_config: KernelConfig, kernel_elf: ElfFile, monitor_elf: ElfFile, system: SystemDescription, invocation_table_size: usize, system_cnode_size: usize, search_paths: Vec<&str>) -> BuiltSystem {
    assert!(util::is_power_of_two(system_cnode_size));
    assert!(invocation_table_size % kernel_config.minimum_page_size == 0);
    assert!(invocation_table_size <= MAX_SYSTEM_INVOCATION_SIZE);

    // TODO: cap address names

    // Emulate kernel boot

    // Determine physical memory region used by the monitor
    let initial_task_size = phys_mem_region_from_elf(monitor_elf, kernel_config.minimum_page_size).size();

    // Get the elf files for each pd:
    // TODO: remove unwraps
    let pd_elf_files: Vec<ElfFile> = system.protection_domains.iter()
                                                              .map(|pd| ElfFile::from_path(&get_full_path(&pd.program_image, &search_paths).unwrap()).unwrap())
                                                              .collect();

    BuiltSystem {}
}

fn main() {
    let arg_sdf_path = std::env::args().nth(1).expect("no system description path given");
    let xml: String = fs::read_to_string(arg_sdf_path).unwrap();
    let system = parse(&xml);

    for pd in &system.protection_domains {
        println!("PD: {:?}", pd);
    }

    let kernel_config = KernelConfig {
        word_size: 64,
        minimum_page_size: 4096,
        paddr_user_device_top: 1 << 40,
        kernel_frame_size: 1 << 12,
        init_cnode_bits: 12,
        cap_address_bits: 64,
        fan_out_limit: 256,
    };

    // TODO: need to test what happens when these paths do not exist
    // and do error checking.
    let kernel_elf = ElfFile::from_path(Path::new("testing/sel4.elf")).unwrap();
    let monitor_elf = ElfFile::from_path(Path::new("testing/monitor.elf")).unwrap();
    let loader_elf = ElfFile::from_path(Path::new("testing/loader.elf")).unwrap();

    let search_paths = vec!["testing"];

    // TODO: do not hardcode
    let board = "qemu_virt_aarch64";
    let config = "debug";

    // 1. Parse the arguments
    // 2. Parse the XML description
    // 3. Parse the kernel ELF
    // 4. Construct the kernel config
    // 5. Parse the monitor ELF
    // 6. Build the system

    let invocation_table_size = kernel_config.minimum_page_size;
    let system_cnode_size = 2;

    loop {
        let built_system = build_system(
            kernel_config,
            kernel_elf,
            monitor_elf,
            system,
            invocation_table_size,
            system_cnode_size,
            search_paths
        );
        println!("BUILT: TODO");
        break;
    }
}
