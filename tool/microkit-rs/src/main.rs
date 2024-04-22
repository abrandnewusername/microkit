mod sysxml;
mod util;
mod elf;
mod sel4;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use sysxml::{parse, SystemDescription, ProtectionDomain};
use elf::ElfFile;
use sel4::{Invocation, Object, Rights};

const INPUT_CAP_IDX: usize = 1;
const FAULT_EP_CAP_IDX: usize = 2;
const VSPACE_CAP_IDX: usize = 3;
const REPLY_CAP_IDX: usize = 4;
const MONITOR_EP_CAP_IDX: usize = 5;
const BASE_OUTPUT_NOTIFICATION_CAP: usize = 10;
const BASE_OUTPUT_ENDPOINT_CAP: usize = BASE_OUTPUT_NOTIFICATION_CAP + 64;
const BASE_IRQ_CAP: usize = BASE_OUTPUT_ENDPOINT_CAP + 64;
const MAX_SYSTEM_INVOCATION_SIZE: u64 = util::mb(128) as u64;
const PD_CAPTABLE_BITS: usize = 12;
const PD_CAP_SIZE: usize = 256;
const PD_CAP_BITS: usize = PD_CAP_SIZE.ilog2() as usize;
const PD_SCHEDCONTEXT_SIZE: usize = 1 << 8;

const SLOT_BITS: u64 = 5;
const SLOT_SIZE: u64 = 1 << SLOT_BITS;

const INIT_NULL_CAP_ADDRESS: u64 = 0;
const INIT_TCB_CAP_ADDRESS: u64 = 1;
const INIT_CNODE_CAP_ADDRESS: u64 = 2;
const INIT_VSPACE_CAP_ADDRESS: u64 = 3;
const IRQ_CONTROL_CAP_ADDRESS: u64 = 4; // Singleton
const ASID_CONTROL_CAP_ADDRESS: u64 = 5; // Singleton
const INIT_ASID_POOL_CAP_ADDRESS: u64 = 6;
const IO_PORT_CONTROL_CAP_ADDRESS: u64 = 7; // Null on this platform
const IO_SPACE_CAP_ADDRESS: u64 = 8;  // Null on this platform
const BOOT_INFO_FRAME_CAP_ADDRESS: u64 = 9;
const INIT_THREAD_IPC_BUFFER_CAP_ADDRESS: u64 = 10;
const DOMAIN_CAP_ADDRESS: u64 = 11;
const SMMU_SID_CONTROL_CAP_ADDRESS: u64 = 12;
const SMMU_CB_CONTROL_CAP_ADDRESS: u64 = 13;
const INIT_THREAD_SC_CAP_ADDRESS: u64 = 14;

#[derive(Copy, Clone)]
struct MemoryRegion {
    /// Note: base is inclusive, end is exclusive
    /// MemoryRegion(1, 5) would have a size of 4
    /// and cover [1, 2, 3, 4]
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

    pub fn aligned_power_of_two_regions(&self) -> Vec<MemoryRegion> {
        let max_bits = 47;
        assert!(false, "fixup lsb and msb");
        // TODO: comment seems weird?
        // Align
        // find the first bit self
        let mut regions = Vec::new();
        let mut base = self.base;
        let mut end = self.end;
        let mut bits;
        while base != end {
            let size = end - base;
            let size_bits = util::msb(size);
            if base == 0 {
                bits = size_bits;
            } else {
                bits = std::cmp::min(size_bits, util::lsb(base));
            }

            if bits > max_bits {
                bits = max_bits;
            }
            let sz = 1 << bits;
            regions.push(MemoryRegion::new(base, base + sz));
            base += sz;
        }

        regions
    }
}

struct DisjointMemoryRegion {
    regions: Vec<MemoryRegion>,
}

impl DisjointMemoryRegion {
    pub fn new() -> DisjointMemoryRegion {
        DisjointMemoryRegion { regions: Vec::new() }
    }

    fn check(&self) {
        // Ensure that regions are sorted and non-overlapping
        let mut last_end: Option<u64> = None;
        for region in &self.regions {
            if last_end.is_some() {
                assert!(region.base >= last_end.unwrap());
            }
            last_end = Some(region.end)
        }
    }

    pub fn insert_region(&mut self, base: u64, end: u64) {
        let mut insert_idx = self.regions.len();
        for (idx, region) in self.regions.iter().enumerate() {
            if end >= region.base {
                insert_idx = idx;
            }
        }
        // FIXME: Should extend here if adjacent rather than
        // inserting now
        self.regions.insert(insert_idx, MemoryRegion::new(base, end));
        self.check();
    }

    pub fn remove_region(&mut self, base: u64, end: u64) -> Result<(), String> {
        let mut idx = self.regions.len();
        for (i, r) in self.regions.iter().enumerate() {
            if base >= r.base && end <= r.end {
                idx = i;
                break;
            }
        }
        // TODO: surely there's a better way to do this?
        if idx == self.regions.len() {
            return Err(format!("Attempting to remove region (0x{:x}-0x{:x} that is not currently covered", base, end));
        }

        let region = self.regions[idx];

        if region.base == base && region.end == end {
            // Covers exactly, so just remove
            self.regions.remove(idx);
        } else if region.base == base {
            // Trim the start of the region
            self.regions[idx] = MemoryRegion::new(end, region.end);
        } else if region.end == end {
            // Trim end of the region
            self.regions[idx] = MemoryRegion::new(region.base, base);
        } else {
            // Splitting
            self.regions[idx] = MemoryRegion::new(region.base, base);
            self.regions.insert(idx + 1, MemoryRegion::new(end, region.end));
        }

        self.check();

        Ok(())
    }

    pub fn aligned_power_of_two_regions(&self) -> Vec<MemoryRegion> {
        let mut aligned_regions = Vec::new();
        for region in &self.regions {
            aligned_regions.extend(region.aligned_power_of_two_regions());
        }

        aligned_regions
    }

    /// Allocate region of 'size' bytes, returning the base address.
    /// The allocated region is removed from the disjoint memory region.
    pub fn allocate(&mut self, size: u64) -> u64 {
        // Allocation policy is simple first fit.
        // Possibly a 'best fit' policy would be better.
        // 'best' may be something that best matches a power-of-two
        // allocation
        let mut region_to_remove: Option<MemoryRegion> = None;
        for region in &self.regions {
            if size <= region.size() {
                region_to_remove = Some(*region);
            }
        }

        if let Some(region) = region_to_remove {
            self.remove_region(region.base, region.base + size);
            return region.base;
        } else {
            panic!("Unable to allocate {} bytes", size);
        }
    }
}

struct KernelConfig {
    // TODO: check the types of these
    word_size: usize,
    minimum_page_size: u64,
    paddr_user_device_top: u64,
    kernel_frame_size: u64,
    init_cnode_bits: u64,
    cap_address_bits: u64,
    fan_out_limit: u64,
}

#[derive(Copy, Clone)]
struct KernelAllocation {
    untyped_cap_address: u64, // FIXME: possibly this is an object, not an int?
    phys_addr: u64,
    allocation_order: u64,
}

impl KernelAllocation {
    pub fn new(untyped_cap_address: u64, phys_addr: u64, allocation_order: u64) -> KernelAllocation {
        KernelAllocation { untyped_cap_address, phys_addr, allocation_order }
    }
}

struct UntypedAllocator {
    untyped_object: UntypedObject,
    allocation_point: u64,
    allocations: Vec<KernelAllocation>,
}

impl UntypedAllocator {
    pub fn new(untyped_object: UntypedObject, allocation_point: u64, allocations: Vec<KernelAllocation>) -> UntypedAllocator {
        UntypedAllocator { untyped_object, allocation_point, allocations }
    }

    pub fn base(&self) -> u64 {
        self.untyped_object.region.base
    }

    pub fn end(&self) -> u64 {
        self.untyped_object.region.end
    }
}

/// Allocator for kernel objects.
///
/// This tracks the space available in a set of untyped objects.
/// On allocation an untyped with sufficient remaining space is
/// returned (while updating the internal tracking).
///
/// Within an untyped object this mimics the kernel's allocation
/// policy (basically a bump allocator with alignment).
///
/// The only 'choice' this allocator has is which untyped object
/// to use. The current algorithm is simply first fit: the first
/// untyped that has sufficient space. This is not optimal.
///
/// Note: The allocator does not generate the Retype invocations;
/// this must be done with more knowledge (specifically the destination
/// cap) which is distinct.
///
/// It is critical that invocations are generated in the same order
/// as the allocations are made.
struct KernelObjectAllocator {
    allocation_idx: u64,
    untyped: Vec<UntypedAllocator>,
}

impl KernelObjectAllocator {
    pub fn new(kernel_boot_info: &KernelBootInfo) -> KernelObjectAllocator {
        let mut untyped = Vec::new();
        for ut in kernel_boot_info.untyped_objects.iter() {
            if ut.is_device {
                // Kernel allocator can only allocate out of normal memory
                // device memory can't be used for kernel objects
                continue;
            }
            untyped.push(UntypedAllocator::new(*ut, 0, vec![]));
        }

        KernelObjectAllocator { allocation_idx: 0, untyped: untyped }
    }

    pub fn alloc(&mut self, size: u64) -> KernelAllocation {
        self.alloc_n(size, 1)
    }

    pub fn alloc_n(&mut self, size: u64, count: u64) -> KernelAllocation {
        assert!(util::is_power_of_two(size));
        for ut in &mut self.untyped {
            // See if this fits
            let start = util::round_up(ut.base() + ut.allocation_point, size);
            self.allocation_idx += 1;
            let allocation = KernelAllocation::new(ut.untyped_object.cap, start, self.allocation_idx);
            ut.allocations.push(allocation);
            return allocation;
        }

        panic!("Can't alloc of size {}, count: {} - no space", size, count);
    }
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

/// Determine the physical memory regions for an ELF file with a given
/// alignment.
///
/// The returned region shall be extended (if necessary) so that the start
/// and end are congruent with the specified alignment (usually a page size).
fn phys_mem_regions_from_elf(elf: &ElfFile, alignment: u64) -> Vec<MemoryRegion> {
    assert!(alignment > 0);

    elf.segments.iter().map(|s| MemoryRegion::new(
        util::round_down(s.phys_addr, alignment),
        util::round_up(s.phys_addr + s.data.len() as u64, alignment),
    )).collect()
}

/// Determine a single physical memory region for an ELF.
///
/// Works as per phys_mem_regions_from_elf, but checks the ELF has a single
/// segment, and returns the region covering the first segment.
fn phys_mem_region_from_elf(elf: &ElfFile, alignment: u64) -> MemoryRegion {
    assert!(alignment > 0);
    assert!(elf.segments.len() == 1);

    phys_mem_regions_from_elf(elf, alignment)[0]
}

/// Determine the virtual memory regions for an ELF file with a given
/// alignment.

/// The returned region shall be extended (if necessary) so that the start
/// and end are congruent with the specified alignment (usually a page size).
fn virt_mem_regions_from_elf(elf: &ElfFile, alignment: u64) -> Vec<MemoryRegion> {
    assert!(alignment > 0);
    elf.segments.iter().map(|s| MemoryRegion::new(
        util::round_down(s.virt_addr, alignment),
        util::round_up(s.virt_addr + s.data.len() as u64, alignment),
    )).collect()
}

/// Determine a single virtual memory region for an ELF.
///
/// Works as per virt_mem_regions_from_elf, but checks the ELF has a single
/// segment, and returns the region covering the first segment.
fn virt_mem_region_from_elf(elf: &ElfFile, alignment: u64) -> MemoryRegion {
    assert!(alignment > 0);
    assert!(elf.segments.len() == 1);

    virt_mem_regions_from_elf(elf, alignment)[0]
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

struct KernelPartialBootInfo {
    device_memory: DisjointMemoryRegion,
    normal_memory: DisjointMemoryRegion,
    boot_region: MemoryRegion,
}

// Corresponds to kernel_frame_t in the kernel
#[repr(C)]
struct KernelFrame64 {
    pub paddr: u64,
    pub pptr: u64,
    pub execute_never: u32,
    pub user_accessible: u32,
}

fn kernel_device_addrs(kernel_config: &KernelConfig, kernel_elf: &ElfFile) -> Vec<u64> {
    assert!(kernel_config.word_size == 64, "Unsupported word-size");

    let mut kernel_devices = Vec::new();
    let (vaddr, size) = kernel_elf.find_symbol("kernel_device_frames");
    // TODO: don't unwrap
    let kernel_frame_bytes = kernel_elf.get_data(vaddr, size).unwrap();
    let kernel_frame_size = std::mem::size_of::<KernelFrame64>();
    let mut offset: usize = 0;
    while offset < size as usize {
        // TODO: check result of align_to
        let (_, kernel_frame_body, _) = unsafe { kernel_frame_bytes[offset..offset + kernel_frame_size].align_to::<KernelFrame64>() };
        let kernel_frame = &kernel_frame_body[0];
        if kernel_frame.user_accessible == 0 {
            kernel_devices.push(kernel_frame.paddr);
        }
        offset += kernel_frame_size;
    }

    kernel_devices
}

// Corresponds to p_region_t in the kernel
#[repr(C)]
struct KernelRegion64 {
    start: u64,
    end: u64,
}

fn kernel_phys_mem(kernel_config: &KernelConfig, kernel_elf: &ElfFile) -> Vec<(u64, u64)> {
    assert!(kernel_config.word_size == 64, "Unsupported word-size");
    let mut phys_mem = Vec::new();
    let (vaddr, size) = kernel_elf.find_symbol("avail_p_regs");
        // TODO: don't unwrap
    let p_region_bytes = kernel_elf.get_data(vaddr, size).unwrap();
    let p_region_size = std::mem::size_of::<KernelRegion64>();
    let mut offset: usize = 0;
    while offset < size as usize {
        // TODO: check result of align_to
        let (_, p_region_body, _) = unsafe { p_region_bytes[offset..offset + p_region_size].align_to::<KernelRegion64>() };
        let p_region = &p_region_body[0];
        phys_mem.push((p_region.start, p_region.end));
        offset += p_region_size;
    }

    phys_mem
}

fn kernel_self_mem(kernel_elf: &ElfFile) -> MemoryRegion {
    // TODO: check this function
    let base = kernel_elf.segments[0].phys_addr;
    let (ki_end_v, _) = kernel_elf.find_symbol("ki_end");
    let ki_end_p = ki_end_v - kernel_elf.segments[0].virt_addr + base;

    MemoryRegion::new(base, ki_end_p)
}

fn kernel_boot_mem(kernel_elf: &ElfFile) -> MemoryRegion {
    // TODO: check this function
    let base = kernel_elf.segments[0].phys_addr;
    let (ki_boot_end_v, _) = kernel_elf.find_symbol("ki_boot_end");
    let ki_boot_end_p = ki_boot_end_v - kernel_elf.segments[0].virt_addr + base;

    MemoryRegion::new(base, ki_boot_end_p)
}

///
/// Emulate what happens during a kernel boot, up to the point
/// where the reserved region is allocated.
///
/// This factors the common parts of 'emulate_kernel_boot' and
/// 'emulate_kernel_boot_partial' to avoid code duplication.
///
fn kernel_partial_boot(kernel_config: &KernelConfig, kernel_elf: &ElfFile) -> KernelPartialBootInfo {
    // Determine the untyped caps of the system
    // This lets allocations happen correctly.
    let mut device_memory = DisjointMemoryRegion::new();
    let mut normal_memory = DisjointMemoryRegion::new();

    // Start by allocating the entire physical address space
    // as device memory.
    device_memory.insert_region(0, kernel_config.paddr_user_device_top);

    // Next, remove all the kernel devices.
    // NOTE: There is an assumption each kernel device is one frame
    // in size only. It's possible this assumption could break in the
    // future.
    for paddr in kernel_device_addrs(kernel_config, kernel_elf) {
        let res = device_memory.remove_region(paddr, paddr + kernel_config.kernel_frame_size);
        assert!(res.is_ok());
    }

    // Remove all the actual physical memory from the device regions
    // but add it all to the actual normal memory regions
    for (start, end) in kernel_phys_mem(kernel_config, kernel_elf) {
        let res = device_memory.remove_region(start, end);
        assert!(res.is_ok());
        normal_memory.insert_region(start, end);
    }

    // Remove the kernel image itself
    let self_mem = kernel_self_mem(kernel_elf);
    normal_memory.remove_region(self_mem.base, self_mem.end);

    // but get the boot region, we'll add that back later
    // FIXME: Why calcaultae it now if we add it back later?
    let boot_region = kernel_boot_mem(kernel_elf);

    KernelPartialBootInfo { device_memory, normal_memory, boot_region }
}

fn emulate_kernel_boot_partial(kernel_config: &KernelConfig, kernel_elf: &ElfFile) -> DisjointMemoryRegion {
    let partial_info = kernel_partial_boot(kernel_config, kernel_elf);
    partial_info.normal_memory
}

#[derive(Copy, Clone)]
struct UntypedObject {
    cap: u64,
    region: MemoryRegion,
    is_device: bool,
}

impl UntypedObject {
    pub fn new(cap: u64, region: MemoryRegion, is_device: bool) -> UntypedObject {
        UntypedObject { cap, region, is_device }
    }

    pub fn base(&self) -> u64 {
        self.region.base
    }

    pub fn size_bits(&self) -> u64 {
        util::lsb(self.region.size())
    }
}

struct KernelBootInfo {
    fixed_cap_count: u64,
    schedcontrol_cap: u64,
    paging_cap_count: u64,
    page_cap_count: u64,
    untyped_objects: Vec<UntypedObject>,
    first_available_cap: u64,
}

fn get_n_paging(region: MemoryRegion, bits: u64) -> u64 {
    let start = util::round_down(region.base, 1 << bits);
    let end = util::round_up(region.end, 1 << bits);

    (end - start) / (1 << bits)
}

fn get_arch_n_paging(region: MemoryRegion) -> u64 {
    const PT_INDEX_OFFSET: u64 = 12;
    const PD_INDEX_OFFSET: u64 = PT_INDEX_OFFSET + 9;
    const PUD_INDEX_OFFSET: u64 = PD_INDEX_OFFSET + 9;
    const PGD_INDEX_OFFSET: u64 = PUD_INDEX_OFFSET + 9;

    get_n_paging(region, PGD_INDEX_OFFSET) +
    get_n_paging(region, PUD_INDEX_OFFSET) +
    get_n_paging(region, PD_INDEX_OFFSET)
}

fn rootserver_max_size_bits() -> u64 {
    let slot_bits = 5; // seL4_SlotBits
    let root_cnode_bits = 12; // CONFIG_ROOT_CNODE_SIZE_BITS
    let vspace_bits = 12; // seL4_VSpaceBits

    let cnode_size_bits = root_cnode_bits + slot_bits;
    std::cmp::max(cnode_size_bits, vspace_bits)
}

fn calculate_rootserver_size(initial_task_region: MemoryRegion) -> u64 {
    // FIXME: These constants should ideally come from the config / kernel
    // binary not be hard coded here.
    // But they are constant so it isn't too bad.
    // This is specifically for aarch64
    let slot_bits = 5;  // seL4_SlotBits
    let root_cnode_bits = 12;  // CONFIG_ROOT_CNODE_SIZE_BITS
    let tcb_bits = 11;  // seL4_TCBBits
    let page_bits = 12;  // seL4_PageBits
    let asid_pool_bits = 12;  // seL4_ASIDPoolBits
    let vspace_bits = 12;  // seL4_VSpaceBits
    let page_table_bits = 12;  // seL4_PageTableBits
    let min_sched_context_bits = 7;  // seL4_MinSchedContextBits

    let mut size = 0;
    size += 1 << (root_cnode_bits + slot_bits);
    size += 1 << (tcb_bits);
    size += 2 * (1 << page_bits);
    size += 1 << asid_pool_bits;
    size += 1 << vspace_bits;
    size += get_arch_n_paging(initial_task_region) * (1 << page_table_bits);
    size += 1 << min_sched_context_bits;

    return size
}

/// Emulate what happens during a kernel boot, generating a
/// representation of the BootInfo struct.
fn emulate_kernel_boot(kernel_config: &KernelConfig, kernel_elf: &ElfFile, initial_task_phys_region: MemoryRegion, initial_task_virt_region: MemoryRegion, reserved_region: MemoryRegion) -> KernelBootInfo {
    assert!(initial_task_phys_region.size() == initial_task_virt_region.size());
    let partial_info = kernel_partial_boot(&kernel_config, kernel_elf);
    let mut normal_memory = partial_info.normal_memory;
    let device_memory = partial_info.device_memory;
    let boot_region = partial_info.boot_region;

    normal_memory.remove_region(initial_task_phys_region.base, initial_task_phys_region.end);
    normal_memory.remove_region(reserved_region.base, reserved_region.end);

    /// Now, the tricky part! determine which memory is used for the initial task objects
    let initial_objects_size = calculate_rootserver_size(initial_task_virt_region);
    let initial_objects_align = rootserver_max_size_bits();

    /// Find an appropriate region of normal memory to allocate the objects
    /// from; this follows the same algorithm used within the kernel boot code
    /// (or at least we hope it does!)
    // TOOD: this loop could be done better in a functional way?
    let mut region_to_remove: Option<u64> = None;
    for region in normal_memory.regions.iter().rev() {
        let start = util::round_down(region.end - initial_objects_size, 1 << initial_objects_align);
        if start >= region.base {
            region_to_remove = Some(start);
        }
    }
    if let Some(start) = region_to_remove {
        normal_memory.remove_region(start, start + initial_objects_size);
    } else {
        panic!("Couldn't find appropriate region for initial task kernel objects");
    }

    let fixed_cap_count = 0x10;
    let sched_control_cap_count = 1;
    let paging_cap_count = get_arch_n_paging(initial_task_virt_region);
    let page_cap_count = initial_task_virt_region.size() / kernel_config.minimum_page_size;
    let first_untyped_cap = fixed_cap_count + paging_cap_count + sched_control_cap_count + page_cap_count;
    let schedcontrol_cap = fixed_cap_count + paging_cap_count;

    // TODO: this is doing a bunch of unecessary copies
    let device_regions: Vec<MemoryRegion> = [reserved_region.aligned_power_of_two_regions().as_slice(), device_memory.aligned_power_of_two_regions().as_slice()].concat();
    let normal_regions: Vec<MemoryRegion> = [boot_region.aligned_power_of_two_regions().as_slice(), normal_memory.aligned_power_of_two_regions().as_slice()].concat();
    let mut untyped_objects = Vec::new();
    for (cap, r) in device_regions[first_untyped_cap as usize..].into_iter().enumerate() {
        untyped_objects.push(UntypedObject::new(cap as u64, *r, true));
    }
    // TODO: check logic
    let normal_cap_start = device_regions.len() + 1;
    for (cap, r) in normal_regions[normal_cap_start..].into_iter().enumerate() {
        untyped_objects.push(UntypedObject::new(cap as u64, *r, false));
    }

    let first_available_cap = first_untyped_cap + device_regions.len() as u64 + normal_regions.len() as u64;
    KernelBootInfo {
        fixed_cap_count,
        paging_cap_count,
        page_cap_count,
        schedcontrol_cap,
        first_available_cap,
        untyped_objects,
    }
}

fn build_system(kernel_config: KernelConfig, kernel_elf: ElfFile, monitor_elf: ElfFile, system: SystemDescription, invocation_table_size: u64, system_cnode_size: u64, search_paths: Vec<&str>) -> BuiltSystem {
    assert!(util::is_power_of_two(system_cnode_size));
    assert!(invocation_table_size % kernel_config.minimum_page_size == 0);
    assert!(invocation_table_size <= MAX_SYSTEM_INVOCATION_SIZE);

    let mut cap_address_names: HashMap<u64, &str> = HashMap::new();
    cap_address_names.insert(INIT_NULL_CAP_ADDRESS, "null");
    cap_address_names.insert(INIT_TCB_CAP_ADDRESS, "TCB: init");
    cap_address_names.insert(INIT_CNODE_CAP_ADDRESS, "CNode: init");
    cap_address_names.insert(INIT_VSPACE_CAP_ADDRESS, "VSpace: init");
    cap_address_names.insert(INIT_ASID_POOL_CAP_ADDRESS, "ASID Pool: init");
    cap_address_names.insert(IRQ_CONTROL_CAP_ADDRESS, "IRQ Control");

    let system_cnode_bits = system_cnode_size.ilog2() as u64;

    // Emulate kernel boot

    // Determine physical memory region used by the monitor
    let initial_task_size = phys_mem_region_from_elf(&monitor_elf, kernel_config.minimum_page_size).size();

    // Get the elf files for each pd:
    // TODO: remove unwraps
    let elf_files: Vec<(&ProtectionDomain, ElfFile)> = system.protection_domains
                                                    .iter()
                                                    .map(|pd| (pd, ElfFile::from_path(&get_full_path(&pd.program_image, &search_paths).unwrap()).unwrap()))
                                                    .collect();
    // TODO: let's go with this hashmap for now, but unsure if it's the correct method.
    let pd_elf_files: HashMap<&ProtectionDomain, ElfFile> = elf_files.into_iter().collect();

    // Determine physical memory region for 'reserved' memory.
    //
    // The 'reserved' memory region will not be touched by seL4 during boot
    // and allows the monitor (initial task) to create memory regions
    // from this area, which can then be made available to the appropriate
    // protection domains
    let mut pd_elf_size = 0;
    for (pd, pd_elf) in pd_elf_files.into_iter() {
        for r in phys_mem_regions_from_elf(&pd_elf, kernel_config.minimum_page_size) {
            pd_elf_size += r.size();
        }
    }
    let reserved_size = invocation_table_size as u64 + pd_elf_size;

    // Now that the size is determined, find a free region in the physical memory
    // space.
    let mut available_memory = emulate_kernel_boot_partial(&kernel_config, &kernel_elf);

    let reserved_base = available_memory.allocate(reserved_size);
    let initial_task_phys_base = available_memory.allocate(initial_task_size);
    // The kernel relies on this ordering. The previous allocation functions do *NOT* enforce
    // this though, should fix that.
    assert!(reserved_base < initial_task_phys_base);

    let initial_task_phys_region = MemoryRegion::new(initial_task_phys_base, initial_task_phys_base + initial_task_size);
    let initial_task_virt_region = virt_mem_region_from_elf(&monitor_elf, kernel_config.minimum_page_size);

    let reserved_region = MemoryRegion::new(reserved_base, reserved_base + reserved_size);

    /// Now that the reserved region has been allocated we can determine the specific
    /// region of physical memory required for the inovcation table itself, and
    /// all the ELF segments
    let invocation_table_region = MemoryRegion::new(reserved_base, reserved_base + invocation_table_size);

    // let mut phys_addr_next = invocation_table_region.end;
    // Now we create additional MRs (and mappings) for the ELF files.
    // let pd_elf_regions: HashMap<&ProtectionDomain, Vec<(u64, Vec<u8>, u8)>> = HashMap::new();
    // for pd in system.protection_domains {
    //     let elf_regions = Vec::new();
    //     let mut seg_idx = 0;
    //     for segment in pd_elf_files.get(pd).segments: {
    //         if !segment.loadable {
    //             continue;
    //         }

    //         let mut perms = 0;
    //         if segment.is_readable() {
    //             perms |= 
    //         }
    //     }
    // }


    // 1.3 With both the initial task region and reserved region determined the kernel
    // boot can be emulated. This provides the boot info information which is needed
    // for the next steps
    let kernel_boot_info = emulate_kernel_boot(
        &kernel_config,
        &kernel_elf,
        initial_task_phys_region,
        initial_task_virt_region,
        reserved_region
    );

    // The kernel boot info allows us to create an allocator for kernel objects
    let mut kao = KernelObjectAllocator::new(&kernel_boot_info);

    // 2. Now that the available resources are known it is possible to proceed with the
    // monitor task boot strap.
    //
    // The boot strap of the monitor works in two phases:
    //
    //   1. Setting up the monitor's CSpace
    //   2. Making the system invocation table available in the monitor's address
    //   space.

    // 2.1 The monitor's CSpace consists of two CNodes: a/ the initial task CNode
    // which consists of all the fixed initial caps along with caps for the
    // object create during kernel bootstrap, and b/ the system CNode, which
    // contains caps to all objects that will be created in this process.
    // The system CNode is of `system_cnode_size`. (Note: see also description
    // on how `system_cnode_size` is iteratively determined).
    //
    // The system CNode is not available at startup and must be created (by retyping
    // memory from an untyped object). Once created the two CNodes must be aranged
    // as a tree such that the slots in both CNodes are addressable.
    //
    // The system CNode shall become the root of the CSpace. The initial CNode shall
    // be copied to slot zero of the system CNode. In this manner all caps in the initial
    // CNode will keep their original cap addresses. This isn't required but it makes
    // allocation, debugging and reasoning about the system more straight forward.
    //
    // The guard shall be selected so the least significant bits are used. The guard
    // for the root shall be:
    //
    //   64 - system cnode bits - initial cnode bits
    //
    // The guard for the initial CNode will be zero.
    //
    // 2.1.1: Allocate the *root* CNode. It is two entries:
    //  slot 0: the existing init cnode
    //  slot 1: our main system cnode
    let root_cnode_bits = 1;
    let root_cnode_allocation = kao.alloc((1 << root_cnode_bits) * (1 << SLOT_BITS));
    let root_cnode_cap = kernel_boot_info.first_available_cap;
    cap_address_names.insert(root_cnode_cap, "CNode: root");

    // 2.1.2: Allocate the *system* CNode. It is the cnodes that
    // will have enough slots for all required caps.
    let system_cnode_allocation = kao.alloc(system_cnode_size * (1 << SLOT_BITS));
    let system_cnode_cap = kernel_boot_info.first_available_cap + 1;
    cap_address_names.insert(system_cnode_cap, "CNode: system");

    // 2.1.3: Now that we've allocated the space for these we generate
    // the actual systems calls.
    //
    // First up create the root cnode
    let mut bootstrap_invocations = Vec::new();

    bootstrap_invocations.push(Invocation::UntypedRetype{
        untyped: root_cnode_allocation.untyped_cap_address,
        object_type: Object::CNode as u64,
        size_bits: root_cnode_bits,
        root: INIT_CNODE_CAP_ADDRESS,
        node_index: 0,
        node_depth: 0,
        node_offset: root_cnode_cap,
        num_objects: 1,
    });


    // 2.1.4: Now insert a cap to the initial Cnode into slot zero of the newly
    // allocated root Cnode. It uses sufficient guard bits to ensure it is
    // completed padded to word size
    //
    // guard size is the lower bit of the guard, upper bits are the guard itself
    // which for out purposes is always zero.
    let guard = kernel_config.cap_address_bits - root_cnode_bits - kernel_config.init_cnode_bits;
    bootstrap_invocations.push(Invocation::CnodeMint{
        cnode: root_cnode_cap,
        dest_index: 0,
        dest_depth: root_cnode_bits,
        src_root: INIT_CNODE_CAP_ADDRESS,
        src_obj: INIT_CNODE_CAP_ADDRESS,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: guard,
    });

    // 2.1.5: Now it is possible to switch our root Cnode to the newly create
    // root cnode. We have a zero sized guard. This Cnode represents the top
    // bit of any cap addresses.
    let root_guard = 0;
    bootstrap_invocations.push(Invocation::TcbSetSpace{
        tcb: INIT_TCB_CAP_ADDRESS,
        fault_ep: INIT_NULL_CAP_ADDRESS,
        cspace_root: root_cnode_cap,
        cspace_root_data: root_guard,
        vspace_root: INIT_VSPACE_CAP_ADDRESS,
        vspace_root_data: 0,
    });

    // 2.1.6: Now we can create our new system Cnode. We will place it into
    // a temporary cap slot in the initial CNode to start with.
    bootstrap_invocations.push(Invocation::UntypedRetype{
        untyped: system_cnode_allocation.untyped_cap_address,
        object_type: Object::CNode as u64,
        size_bits: system_cnode_bits,
        root: INIT_CNODE_CAP_ADDRESS,
        node_index: 0,
        node_depth: 0,
        node_offset: system_cnode_cap,
        num_objects: 1
    });

    // 2.1.7: Now that the we have create the object, we can 'mutate' it
    // to the correct place:
    // Slot #1 of the new root cnode
    // TODO: not sure if system_guard is a good name
    let system_guard = kernel_config.cap_address_bits - root_cnode_bits - system_cnode_bits;
    let system_cap_address_mask = 1 << (kernel_config.cap_address_bits - 1);
    bootstrap_invocations.push(Invocation::CnodeMint{
        cnode: root_cnode_cap,
        dest_index: 1,
        dest_depth: root_cnode_bits,
        src_root: INIT_CNODE_CAP_ADDRESS,
        src_obj: system_cnode_cap,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: system_guard
    });

    // 2.2 At this point it is necessary to get the frames containing the
    // main system invocations into the virtual address space. (Remember the
    // invocations we are writing out here actually _execute_ at run time!
    // It is a bit weird that we talk about mapping in the invocation data
    // before we have even generated the invocation data!).
    //
    // This needs a few steps:
    //
    // 1. Turn untyped into page objects
    // 2. Map the page objects into the address space
    //

    // 2.2.1: The memory for the system invocation data resides at the start
    // of the reserved region. We can retype multiple frames as a time (
    // which reduces the number of invocations we need). However, it is possible
    // that the region spans multiple untyped objects.
    // At this point in time we assume we will map the area using the minimum
    // page size. It would be good in the future to use super pages (when
    // it makes sense to - this would reduce memory usage, and the number of
    // invocations required to set up the address space

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
