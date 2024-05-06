mod sysxml;
pub mod util;
mod elf;
mod sel4;
mod loader;

use std::collections::{HashMap, HashSet};
use std::iter::zip;
use std::fmt;
use std::fs;
use std::cmp::{max,min};
use std::path::{Path, PathBuf};
use sysxml::{parse, SystemDescription, ProtectionDomain, SysMap, SysMapPerms, SysMemoryRegion};
use elf::ElfFile;
use sel4::{Invocation, InvocationArgs, ObjectType, Rights, PageSize, Aarch64Regs};
use std::io::{Write, BufWriter};
use std::mem::size_of;
use loader::Loader;
use util::struct_to_bytes;

const MAX_PDS: usize = 64;
// It should be noted that if you were to change the value of
// the maximum PD name length, you would also have to change
// the monitor and libmicrokit.
const PD_MAX_NAME_LENGTH: usize = 16;

const SYMBOL_IPC_BUFFER: &str = "__sel4_ipc_buffer_obj";

// TODO: use a better typed thing?
const SEL4_ARM_PAGE_CACHEABLE: u64 = 1;
const SEL4_ARM_PARITY_ENABLED: u64 = 2;
const SEL4_ARM_EXECUTE_NEVER: u64 = 4;
const SEL4_ARM_DEFAULT_VMATTRIBUTES: u64 = 3;

const INPUT_CAP_IDX: u64 = 1;
#[allow(dead_code)]
// TODO: actually, I really don't understand why this is never used
const FAULT_EP_CAP_IDX: u64 = 2;
const VSPACE_CAP_IDX: u64 = 3;
const REPLY_CAP_IDX: u64 = 4;
const MONITOR_EP_CAP_IDX: u64 = 5;
const BASE_OUTPUT_NOTIFICATION_CAP: u64 = 10;
const BASE_OUTPUT_ENDPOINT_CAP: u64 = BASE_OUTPUT_NOTIFICATION_CAP + 64;
const BASE_IRQ_CAP: u64 = BASE_OUTPUT_ENDPOINT_CAP + 64;
const MAX_SYSTEM_INVOCATION_SIZE: u64 = util::mb(128) as u64;
const PD_CAP_SIZE: u64 = 256;
const PD_CAP_BITS: u64 = PD_CAP_SIZE.ilog2() as u64;
const PD_SCHEDCONTEXT_SIZE: u64 = 1 << 8;

const SLOT_BITS: u64 = 5;
const SLOT_SIZE: u64 = 1 << SLOT_BITS;

const INIT_NULL_CAP_ADDRESS: u64 = 0;
const INIT_TCB_CAP_ADDRESS: u64 = 1;
const INIT_CNODE_CAP_ADDRESS: u64 = 2;
const INIT_VSPACE_CAP_ADDRESS: u64 = 3;
const IRQ_CONTROL_CAP_ADDRESS: u64 = 4; // Singleton
// const ASID_CONTROL_CAP_ADDRESS: u64 = 5; // Singleton
const INIT_ASID_POOL_CAP_ADDRESS: u64 = 6;
// const IO_PORT_CONTROL_CAP_ADDRESS: u64 = 7; // Null on this platform
// const IO_SPACE_CAP_ADDRESS: u64 = 8;  // Null on this platform
// const BOOT_INFO_FRAME_CAP_ADDRESS: u64 = 9;
// const INIT_THREAD_IPC_BUFFER_CAP_ADDRESS: u64 = 10;
// const DOMAIN_CAP_ADDRESS: u64 = 11;
// const SMMU_SID_CONTROL_CAP_ADDRESS: u64 = 12;
// const SMMU_CB_CONTROL_CAP_ADDRESS: u64 = 13;
// const INIT_THREAD_SC_CAP_ADDRESS: u64 = 14;

/// Corresponds to 'struct untyped_info' in the monitor
/// It should be noted that this is called a 'header' since
/// it omits the 'regions' field.
/// This struct assumes a 64-bit target
#[repr(C)]
struct MonitorUntypedInfoHeader64 {
    cap_start: u64,
    cap_end: u64,
}

/// Corresponds to 'struct region' in the monitor
/// This struct assumes a 64-bit target
#[repr(C)]
struct MonitorRegion64 {
    paddr: u64,
    size_bits: u64,
    is_device: u64,
}

struct MonitorConfig {
    untyped_info_symbol_name: &'static str,
    bootstrap_invocation_count_symbol_name: &'static str,
    bootstrap_invocation_data_symbol_name: &'static str,
    system_invocation_count_symbol_name: &'static str,
}

impl MonitorConfig {
    pub fn max_untyped_objects(&self, symbol_size: u64) -> u64 {
        (symbol_size - size_of::<MonitorUntypedInfoHeader64>() as u64) / size_of::<MonitorRegion64>() as u64
    }
}

/// Represents an allocated kernel object.
///
/// Kernel objects can have multiple caps (and caps can have multiple addresses).
/// The cap referred to here is the original cap that is allocated when the
/// kernel object is first allocate.
/// The cap_slot refers to the specific slot in which this cap resides.
/// The cap_address refers to a cap address that addresses this cap.
/// The cap_address is is intended to be valid within the context of the
/// initial task.
#[derive(Clone)]
pub struct KernelObject {
    name: String,
    /// Type of kernel object
    object_type: ObjectType,
    cap_addr: u64,
    /// Physical memory address of the kernel object
    phys_addr: u64,
}

#[derive(Debug)]
struct FixedUntypedAlloc {
    ut: UntypedObject,
    watermark: u64,
}

impl FixedUntypedAlloc {
    pub fn new(ut: UntypedObject) -> FixedUntypedAlloc {
        FixedUntypedAlloc { ut, watermark: ut.base() }
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.ut.base() <= addr && addr < self.ut.end()
    }
}

struct InitSystem<'a> {
    kernel_config: &'a KernelConfig,
    cnode_cap: u64,
    cnode_mask: u64,
    kao: &'a mut KernelObjectAllocator,
    invocations: &'a mut Vec<Invocation>,
    cap_slot: u64,
    last_fixed_address: u64,
    device_untyped: Vec<FixedUntypedAlloc>,
    cap_address_names: &'a mut HashMap<u64, String>,
    objects: Vec<KernelObject>,
}

impl<'a> InitSystem<'a> {
    pub fn new(kernel_config: &'a KernelConfig,
               cnode_cap: u64,
               cnode_mask: u64,
               first_available_cap_slot: u64,
               kernel_object_allocator: &'a mut KernelObjectAllocator,
               kernel_boot_info: &'a KernelBootInfo,
               invocations: &'a mut Vec<Invocation>,
               cap_address_names: &'a mut HashMap<u64, String>,
               ) -> InitSystem<'a> {
        let mut device_untyped: Vec<FixedUntypedAlloc> = kernel_boot_info.untyped_objects
                            .iter()
                            .filter_map(|ut| {
                                if ut.is_device {
                                    Some(FixedUntypedAlloc::new(*ut))
                                } else {
                                    None
                                }
                            })
                            .collect();
        device_untyped.sort_by(|a, b| {
            if a.ut.base() < b.ut.base() {
                std::cmp::Ordering::Less
            } else if a.ut.base() == b.ut.base() {
                std::cmp::Ordering::Equal
            } else {
                std::cmp::Ordering::Greater
            }
        });

        InitSystem {
            kernel_config: kernel_config,
            cnode_cap: cnode_cap,
            cnode_mask: cnode_mask,
            kao: kernel_object_allocator,
            invocations: invocations,
            cap_slot: first_available_cap_slot,
            last_fixed_address: 0,
            device_untyped: device_untyped,
            cap_address_names: cap_address_names,
            objects: Vec::new(),
        }
    }

    pub fn reserve(&mut self, allocations: Vec<(&UntypedObject, u64)>) {
        for (alloc_ut, alloc_phys_addr) in allocations {
            for fut in &mut self.device_untyped {
                if *alloc_ut == fut.ut {
                    if fut.ut.base() <= alloc_phys_addr && alloc_phys_addr <= fut.ut.end() {
                        fut.watermark = alloc_phys_addr;
                        return;
                    } else {
                        // TODO: use display trait instead
                        panic!("Allocation {:?} ({:x}) not in untyped region {:?}", alloc_ut, alloc_phys_addr, fut.ut.region);
                    }
                }
            }

            // TODO: use display trait instead
            panic!("Allocation {:?} ({:x}) not in any device untyped", alloc_ut, alloc_phys_addr);
        }
    }

    /// Note: Fixed objects must be allocated in order!
    pub fn allocate_fixed_objects(&mut self, phys_address: u64, object_type: ObjectType, count: u64, names: Vec<String>) -> Vec<KernelObject> {
        assert!(phys_address >= self.last_fixed_address);
        assert!(object_type.fixed_size().is_some());
        assert!(count == names.len() as u64);
        assert!(count > 0);

        let alloc_size = object_type.fixed_size().unwrap();
        // Find an untyped that contains the given address
        let fut: &mut FixedUntypedAlloc = self.device_untyped
                    .iter_mut()
                    .find(|fut| fut.contains(phys_address))
                    .expect(format!("physical address {:x} not in any device untyped", phys_address).as_str());

        if phys_address < fut.watermark {
            panic!("physical address {:x} is below watermark", phys_address);
        }

        if fut.watermark != phys_address {
            // If the watermark isn't at the right spot, then we need to
            // create padding objects until it is.
            let mut padding_required = phys_address - fut.watermark;
            // We are restricted in how much we can pad:
            // 1: Untyped objects must be power-of-two sized.
            // 2: Untyped objects must be aligned to their size.
            let mut padding_sizes = Vec::new();
            // We have two potential approaches for how we pad.
            // 1: Use largest objects possible respecting alignment
            // and size restrictions.
            // 2: Use a fixed size object multiple times. This will
            // create more objects, but as same sized objects can be
            // create in a batch, required fewer invocations.
            // For now we choose #1
            let mut wm = fut.watermark;
            while padding_required > 0 {
                let wm_lsb = util::lsb(wm);
                let sz_msb = util::msb(padding_required);
                let pad_obejct_size = 1 << min(wm_lsb, sz_msb);
                padding_sizes.push(pad_obejct_size);
                wm += pad_obejct_size;
                padding_required -= pad_obejct_size;
            }

            for sz in padding_sizes {
                self.invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
                    untyped: fut.ut.cap,
                    object_type: ObjectType::Untyped,
                    size_bits: sz.ilog2() as u64,
                    root: self.cnode_cap,
                    node_index: 1,
                    node_depth: 1,
                    node_offset: self.cap_slot,
                    num_objects: 1,
                }));
                self.cap_slot += 1;
            }
        }

        let object_cap = self.cap_slot;
        self.cap_slot += 1;
        self.invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
            untyped: fut.ut.cap,
            object_type: object_type,
            size_bits: 0,
            root: self.cnode_cap,
            node_index: 1,
            node_depth: 1,
            node_offset: object_cap,
            num_objects: 1,
        }));

        fut.watermark = phys_address + alloc_size;
        self.last_fixed_address = phys_address + alloc_size;
        let cap_addr = self.cnode_mask | object_cap;
        let name = &names[0];
        let kernel_object = KernelObject{
            name: name.clone(),
            object_type,
            cap_addr,
            phys_addr: phys_address,
        };
        self.objects.push(kernel_object.clone());
        self.cap_address_names.insert(cap_addr, name.clone());

        vec![kernel_object]
    }

    pub fn allocate_objects(&mut self, object_type: ObjectType, names: Vec<String>, size: Option<u64>) -> Vec<KernelObject> {
        let count = names.len() as u64;

        // TODO: kinda hacky
        if count == 0 {
            return Vec::new();
        }

        let alloc_size;
        let api_size: u64;
        if let Some(object_size) = object_type.fixed_size() {
            // An object with a fixed size should not be allocated with a given size
            assert!(size.is_none());
            alloc_size = object_size;
            api_size = 0;
        } else if object_type == ObjectType::CNode || object_type == ObjectType::SchedContext {
            assert!(size.is_some());
            // TODO: so many unwraps...
            assert!(util::is_power_of_two(size.unwrap()));
            api_size = size.unwrap().ilog2() as u64;
            alloc_size = size.unwrap() * SLOT_SIZE;
        } else {
            panic!("Invalid object type: {:?}", object_type);
        }

        let allocation = self.kao.alloc_n(alloc_size, count);
        let base_cap_slot = self.cap_slot;
        self.cap_slot += count;

        let mut to_alloc = count;
        let mut alloc_cap_slot = base_cap_slot;
        while to_alloc > 0 {
            let call_count = min(to_alloc, self.kernel_config.fan_out_limit);
            self.invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
                untyped: allocation.untyped_cap_address,
                object_type: object_type,
                size_bits: api_size,
                root: self.cnode_cap,
                node_index: 1,
                node_depth: 1,
                node_offset: alloc_cap_slot,
                num_objects: call_count,
            }));
            to_alloc -= call_count;
            alloc_cap_slot += call_count;
        }

        let mut kernel_objects = Vec::new();
        let mut phys_addr = allocation.phys_addr;
        for idx in 0..count {
            let cap_slot = base_cap_slot + idx;
            let cap_addr = self.cnode_mask | cap_slot;
            let name = &names[idx as usize];
            kernel_objects.push(KernelObject{
                // TODO: not sure if we can get away with removing this clone
                name: name.clone(),
                object_type,
                cap_addr,
                phys_addr,
            });
            self.cap_address_names.insert(cap_addr, name.clone());

            phys_addr += alloc_size;
        }

        // TODO: can we remove this clone?
        self.objects.extend(kernel_objects.clone());

        kernel_objects
    }
}

struct Region {
    name: String,
    addr: u64,
    size: u64,
}


impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: report segment idx?
        write!(f, "<Region name={} addr=0x{:x} size={}>", self.name, self.addr, self.size)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct MemoryRegion {
    /// Note: base is inclusive, end is exclusive
    /// MemoryRegion(1, 5) would have a size of 4
    /// and cover [1, 2, 3, 4]
    base: u64,
    end: u64,
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: could be more consistent with Region?
        write!(f, "MemoryRegion(base=0x{:x}, end=0x{:x})", self.base, self.end)
    }
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
        // TODO: comment seems weird?
        // Align
        // find the first bit self
        let mut regions = Vec::new();
        let mut base = self.base;
        let mut bits;
        while base != self.end {
            let size = self.end - base;
            let size_bits = util::msb(size);
            if base == 0 {
                bits = size_bits;
            } else {
                bits = min(size_bits, util::lsb(base));
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

    pub fn remove_region(&mut self, base: u64, end: u64) {
        let mut idx = self.regions.len();
        for (i, r) in self.regions.iter().enumerate() {
            if base >= r.base && end <= r.end {
                idx = i;
                break;
            }
        }
        // TODO: surely there's a better way to do this?
        if idx == self.regions.len() {
            panic!("Attempting to remove region [0x{:x}-0x{:x}) that is not currently covered", base, end);
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
                break;
            }
        }

        // TODO: not the most ergonomic code, it's structured this way because
        // we have mutable and immutable references - see if we can get around it
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
        assert!(count > 0);
        for ut in &mut self.untyped {
            // See if this fits
            let start = util::round_up(ut.base() + ut.allocation_point, size);
            if start + (count * size) <= ut.end() {
                ut.allocation_point = (start - ut.base()) + (count * size);
                self.allocation_idx += 1;
                let allocation = KernelAllocation { untyped_cap_address: ut.untyped_object.cap, phys_addr: start };
                ut.allocations.push(allocation);
                return allocation;
            }
        }

        panic!("Can't alloc of size {}, count: {} - no space", size, count);
    }
}

struct BuiltSystem {
    number_of_system_caps: u64,
    invocation_data_size: u64,
    bootstrap_invocations: Vec<Invocation>,
    system_invocations: Vec<Invocation>,
    kernel_boot_info: KernelBootInfo,
    reserved_region: MemoryRegion,
    fault_ep_cap_address: u64,
    reply_cap_address: u64,
    cap_lookup: HashMap<u64, String>,
    tcb_caps: Vec<u64>,
    sched_caps: Vec<u64>,
    ntfn_caps: Vec<u64>,
    regions: Vec<Region>,
    kernel_objects: Vec<KernelObject>,
    initial_task_virt_region: MemoryRegion,
    initial_task_phys_region: MemoryRegion,
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
    let kernel_frame_size = size_of::<KernelFrame64>();
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
    let p_region_size = size_of::<KernelRegion64>();
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
        device_memory.remove_region(paddr, paddr + kernel_config.kernel_frame_size);
    }

    // Remove all the actual physical memory from the device regions
    // but add it all to the actual normal memory regions
    for (start, end) in kernel_phys_mem(kernel_config, kernel_elf) {
        device_memory.remove_region(start, end);
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

#[derive(Debug, Copy, Clone, PartialEq)]
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

    pub fn end(&self) -> u64 {
        self.region.end
    }

    pub fn size_bits(&self) -> u64 {
        util::lsb(self.region.size())
    }
}

#[derive(Clone)]
struct KernelBootInfo {
    fixed_cap_count: u64,
    sched_control_cap: u64,
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
    max(cnode_size_bits, vspace_bits)
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

    // Now, the tricky part! determine which memory is used for the initial task objects
    let initial_objects_size = calculate_rootserver_size(initial_task_virt_region);
    let initial_objects_align = rootserver_max_size_bits();

    // Find an appropriate region of normal memory to allocate the objects
    // from; this follows the same algorithm used within the kernel boot code
    // (or at least we hope it does!)
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
    let sched_control_cap = fixed_cap_count + paging_cap_count;

    // TODO: this is doing a bunch of unecessary copies
    let device_regions: Vec<MemoryRegion> = [reserved_region.aligned_power_of_two_regions().as_slice(), device_memory.aligned_power_of_two_regions().as_slice()].concat();
    let normal_regions: Vec<MemoryRegion> = [boot_region.aligned_power_of_two_regions().as_slice(), normal_memory.aligned_power_of_two_regions().as_slice()].concat();
    let mut untyped_objects = Vec::new();
    for (i, r) in device_regions.iter().enumerate() {
        let cap = i as u64 + first_untyped_cap;
        untyped_objects.push(UntypedObject::new(cap, *r, true));
    }
    let normal_regions_start_cap = first_untyped_cap + device_regions.len() as u64;
    for (i, r) in normal_regions.iter().enumerate() {
        let cap = i as u64 + normal_regions_start_cap;
        untyped_objects.push(UntypedObject::new(cap, *r, false));
    }

    let first_available_cap = first_untyped_cap + device_regions.len() as u64 + normal_regions.len() as u64;
    KernelBootInfo {
        fixed_cap_count,
        paging_cap_count,
        page_cap_count,
        sched_control_cap,
        first_available_cap,
        untyped_objects,
    }
}

fn build_system<'a>(kernel_config: &KernelConfig,
                    kernel_elf: &ElfFile,
                    monitor_elf: &ElfFile,
                    system: &'a SystemDescription,
                    invocation_table_size: u64,
                    system_cnode_size: u64,
                    search_paths: &Vec<&str>) -> BuiltSystem {
    assert!(util::is_power_of_two(system_cnode_size));
    assert!(invocation_table_size % kernel_config.minimum_page_size == 0);
    assert!(invocation_table_size <= MAX_SYSTEM_INVOCATION_SIZE);

    let mut cap_address_names: HashMap<u64, String> = HashMap::new();
    cap_address_names.insert(INIT_NULL_CAP_ADDRESS, "null".to_string());
    cap_address_names.insert(INIT_TCB_CAP_ADDRESS, "TCB: init".to_string());
    cap_address_names.insert(INIT_CNODE_CAP_ADDRESS, "CNode: init".to_string());
    cap_address_names.insert(INIT_VSPACE_CAP_ADDRESS, "VSpace: init".to_string());
    cap_address_names.insert(INIT_ASID_POOL_CAP_ADDRESS, "ASID Pool: init".to_string());
    cap_address_names.insert(IRQ_CONTROL_CAP_ADDRESS, "IRQ Control".to_string());

    let system_cnode_bits = system_cnode_size.ilog2() as u64;

    // Emulate kernel boot

    // Determine physical memory region used by the monitor
    let initial_task_size = phys_mem_region_from_elf(&monitor_elf, kernel_config.minimum_page_size).size();

    // Get the elf files for each pd:
    // TODO: remove unwraps
    let elf_files: Vec<(&ProtectionDomain, ElfFile)> = system.protection_domains
                                                    .iter()
                                                    .map(|pd| (pd, ElfFile::from_path(&get_full_path(&pd.program_image, &search_paths).unwrap())))
                                                    .collect();
    // TODO: let's go with this hashmap for now, but unsure if it's the correct method.
    let mut pd_elf_files: HashMap<&ProtectionDomain, ElfFile> = elf_files.into_iter().collect();

    // Determine physical memory region for 'reserved' memory.
    //
    // The 'reserved' memory region will not be touched by seL4 during boot
    // and allows the monitor (initial task) to create memory regions
    // from this area, which can then be made available to the appropriate
    // protection domains
    let mut pd_elf_size = 0;
    for (_, pd_elf) in &pd_elf_files {
        for r in phys_mem_regions_from_elf(pd_elf, kernel_config.minimum_page_size) {
            pd_elf_size += r.size();
        }
    }
    let reserved_size = invocation_table_size as u64 + pd_elf_size;

    // Now that the size is determined, find a free region in the physical memory
    // space.
    let mut available_memory = emulate_kernel_boot_partial(kernel_config, kernel_elf);

    let reserved_base = available_memory.allocate(reserved_size);
    let initial_task_phys_base = available_memory.allocate(initial_task_size);
    // The kernel relies on this ordering. The previous allocation functions do *NOT* enforce
    // this though, should fix that.
    assert!(reserved_base < initial_task_phys_base);

    let initial_task_phys_region = MemoryRegion::new(initial_task_phys_base, initial_task_phys_base + initial_task_size);
    let initial_task_virt_region = virt_mem_region_from_elf(monitor_elf, kernel_config.minimum_page_size);

    let reserved_region = MemoryRegion::new(reserved_base, reserved_base + reserved_size);

    // Now that the reserved region has been allocated we can determine the specific
    // region of physical memory required for the inovcation table itself, and
    // all the ELF segments
    let invocation_table_region = MemoryRegion::new(reserved_base, reserved_base + invocation_table_size);

    // 1.3 With both the initial task region and reserved region determined the kernel
    // boot can be emulated. This provides the boot info information which is needed
    // for the next steps
    let kernel_boot_info = emulate_kernel_boot(
        kernel_config,
        kernel_elf,
        initial_task_phys_region,
        initial_task_virt_region,
        reserved_region
    );

    for ut in &kernel_boot_info.untyped_objects {
        let dev_str = if ut.is_device {
            " (device)"
        } else {
            ""
        };
        let ut_str = format!("Untyped @ 0x{:x}:0x{:x}{}", ut.region.base, ut.region.size(), dev_str);
        cap_address_names.insert(ut.cap, ut_str);
    }

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
    cap_address_names.insert(root_cnode_cap, "CNode: root".to_string());

    // 2.1.2: Allocate the *system* CNode. It is the cnodes that
    // will have enough slots for all required caps.
    let system_cnode_allocation = kao.alloc(system_cnode_size * (1 << SLOT_BITS));
    let system_cnode_cap = kernel_boot_info.first_available_cap + 1;
    cap_address_names.insert(system_cnode_cap, "CNode: system".to_string());

    // 2.1.3: Now that we've allocated the space for these we generate
    // the actual systems calls.
    //
    // First up create the root cnode
    let mut bootstrap_invocations = Vec::new();

    bootstrap_invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
        untyped: root_cnode_allocation.untyped_cap_address,
        object_type: ObjectType::CNode,
        size_bits: root_cnode_bits,
        root: INIT_CNODE_CAP_ADDRESS,
        node_index: 0,
        node_depth: 0,
        node_offset: root_cnode_cap,
        num_objects: 1,
    }));


    // 2.1.4: Now insert a cap to the initial Cnode into slot zero of the newly
    // allocated root Cnode. It uses sufficient guard bits to ensure it is
    // completed padded to word size
    //
    // guard size is the lower bit of the guard, upper bits are the guard itself
    // which for out purposes is always zero.
    let guard = kernel_config.cap_address_bits - root_cnode_bits - kernel_config.init_cnode_bits;
    bootstrap_invocations.push(Invocation::new(InvocationArgs::CnodeMint{
        cnode: root_cnode_cap,
        dest_index: 0,
        dest_depth: root_cnode_bits,
        src_root: INIT_CNODE_CAP_ADDRESS,
        src_obj: INIT_CNODE_CAP_ADDRESS,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: guard,
    }));

    // 2.1.5: Now it is possible to switch our root Cnode to the newly create
    // root cnode. We have a zero sized guard. This Cnode represents the top
    // bit of any cap addresses.
    let root_guard = 0;
    bootstrap_invocations.push(Invocation::new(InvocationArgs::TcbSetSpace{
        tcb: INIT_TCB_CAP_ADDRESS,
        fault_ep: INIT_NULL_CAP_ADDRESS,
        cspace_root: root_cnode_cap,
        cspace_root_data: root_guard,
        vspace_root: INIT_VSPACE_CAP_ADDRESS,
        vspace_root_data: 0,
    }));

    // 2.1.6: Now we can create our new system Cnode. We will place it into
    // a temporary cap slot in the initial CNode to start with.
    bootstrap_invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
        untyped: system_cnode_allocation.untyped_cap_address,
        object_type: ObjectType::CNode,
        size_bits: system_cnode_bits,
        root: INIT_CNODE_CAP_ADDRESS,
        node_index: 0,
        node_depth: 0,
        node_offset: system_cnode_cap,
        num_objects: 1
    }));

    // 2.1.7: Now that the we have create the object, we can 'mutate' it
    // to the correct place:
    // Slot #1 of the new root cnode
    // TODO: not sure if system_guard is a good name
    let system_guard = kernel_config.cap_address_bits - root_cnode_bits - system_cnode_bits;
    let system_cap_address_mask = 1 << (kernel_config.cap_address_bits - 1);
    bootstrap_invocations.push(Invocation::new(InvocationArgs::CnodeMint{
        cnode: root_cnode_cap,
        dest_index: 1,
        dest_depth: root_cnode_bits,
        src_root: INIT_CNODE_CAP_ADDRESS,
        src_obj: system_cnode_cap,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: system_guard
    }));

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
    let pages_required = invocation_table_size / kernel_config.minimum_page_size;
    let base_page_cap = 0;
    for pta in base_page_cap..base_page_cap + pages_required {
        cap_address_names.insert(system_cap_address_mask | pta, "SmallPage: monitor invocation table".to_string());
    }

    let mut remaining_pages = pages_required;
    let mut invocation_table_allocations = Vec::new();
    let mut cap_slot = base_page_cap;
    let mut phys_addr = invocation_table_region.base;

    let boot_info_device_untypeds: Vec<&UntypedObject> = kernel_boot_info.untyped_objects.iter().filter(|o| o.is_device).collect();
    for ut in boot_info_device_untypeds {
        let ut_pages = ut.region.size() / kernel_config.minimum_page_size;
        let retype_page_count = min(ut_pages, remaining_pages);
        assert!(retype_page_count <= kernel_config.fan_out_limit);
        bootstrap_invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
            untyped: ut.cap,
            object_type: ObjectType::SmallPage,
            size_bits: 0,
            root: root_cnode_cap,
            node_index: 1,
            node_depth: 1,
            node_offset: cap_slot,
            num_objects: retype_page_count,
        }));

        remaining_pages -= retype_page_count;
        cap_slot += retype_page_count;
        phys_addr += retype_page_count * kernel_config.minimum_page_size;
        invocation_table_allocations.push((ut, phys_addr));
        if remaining_pages == 0 {
            break;
        }
    }

    // 2.2.1: Now that physical pages have been allocated it is possible to setup
    // the virtual memory objects so that the pages can be mapped into virtual memory
    // At this point we map into the arbitrary address of 0x0.8000.0000 (i.e.: 2GiB)
    // We arbitrary limit the maximum size to be 128MiB. This allows for at least 1 million
    // invocations to occur at system startup. This should be enough for any reasonable
    // sized system.
    //
    // Before mapping it is necessary to install page tables that can cover the region.
    let page_tables_required = util::round_up(invocation_table_size, sel4::OBJECT_SIZE_LARGE_PAGE) / sel4::OBJECT_SIZE_LARGE_PAGE;
    let page_table_allocation = kao.alloc_n(sel4::OBJECT_SIZE_PAGE_TABLE, page_tables_required);
    let base_page_table_cap = cap_slot;

    for pta in base_page_table_cap..base_page_table_cap + page_tables_required {
        cap_address_names.insert(system_cap_address_mask | pta, "PageTable: monitor".to_string());
    }

    assert!(page_tables_required <= kernel_config.fan_out_limit);
    bootstrap_invocations.push(Invocation::new(InvocationArgs::UntypedRetype{
        untyped: page_table_allocation.untyped_cap_address,
        object_type: ObjectType::PageTable,
        size_bits: 0,
        root: root_cnode_cap,
        node_index: 1,
        node_depth: 1,
        node_offset: cap_slot,
        num_objects: page_tables_required
    }));
    cap_slot += page_tables_required;

    let page_table_vaddr: u64 = 0x8000_0000;
    // Now that the page tables are allocated they can be mapped into vspace
    let mut pt_map_invocation = Invocation::new(InvocationArgs::PageTableMap{
        page_table: system_cap_address_mask | base_page_table_cap,
        vspace: INIT_VSPACE_CAP_ADDRESS,
        vaddr: page_table_vaddr,
        attr: SEL4_ARM_DEFAULT_VMATTRIBUTES,
    });
    pt_map_invocation.repeat(page_tables_required, InvocationArgs::PageTableMap{
        page_table: 1,
        vspace: 0,
        vaddr: ObjectType::LargePage as u64,
        attr: 0,
    });
    bootstrap_invocations.push(pt_map_invocation);

    // Finally, once the page tables are allocated the pages can be mapped
    let page_vaddr: u64 = 0x8000_0000;
    let mut map_invocation = Invocation::new(InvocationArgs::PageMap{
        page: system_cap_address_mask | base_page_cap,
        vspace: INIT_VSPACE_CAP_ADDRESS,
        vaddr: page_vaddr,
        rights: Rights::Read as u64,
        attr: SEL4_ARM_DEFAULT_VMATTRIBUTES | SEL4_ARM_EXECUTE_NEVER
    });
    map_invocation.repeat(pages_required, InvocationArgs::PageMap{
        page: 1,
        vspace: 0,
        vaddr: kernel_config.minimum_page_size,
        rights: 0,
        attr: 0,
    });
    bootstrap_invocations.push(map_invocation);

    // 3. Now we can start setting up the system based on the information
    // the user provided in the System Description Format.
    //
    // Create all the objects:
    //
    //  TCBs: one per PD
    //  Endpoints: one per PD with a PP + one for the monitor
    //  Notification: one per PD
    //  VSpaces: one per PD
    //  CNodes: one per PD
    //  Small Pages:
    //     one per pd for IPC buffer
    //     as needed by MRs
    //  Large Pages:
    //     as needed by MRs
    //  Page table structs:
    //     as needed by protection domains based on mappings required
    let mut phys_addr_next = reserved_base + invocation_table_size;
    // Now we create additional MRs (and mappings) for the ELF files.
    let mut regions = Vec::new();
    let mut extra_mrs = Vec::new();
    let mut pd_extra_maps: HashMap<&ProtectionDomain, Vec<SysMap>> = HashMap::new();
    for pd in &system.protection_domains {
        for (seg_idx, segment) in pd_elf_files[pd].segments.iter().enumerate() {
            if !segment.loadable {
                continue;
            }

            let segment_phys_addr = phys_addr_next + (segment.virt_addr % kernel_config.minimum_page_size);
            regions.push(Region {
                name: format!("PD-ELF {}-{}", pd.name, seg_idx),
                addr: segment_phys_addr,
                size: segment.data.len() as u64,
            });

            let mut perms = 0;
            if segment.is_readable() {
                perms |= SysMapPerms::Read as u8;
            }
            if segment.is_writable() {
                perms |= SysMapPerms::Write as u8;
            }
            if segment.is_executable() {
                perms |= SysMapPerms::Execute as u8;
            }

            let base_vaddr = util::round_down(segment.virt_addr, kernel_config.minimum_page_size);
            let end_vaddr = util::round_up(segment.virt_addr + segment.mem_size(), kernel_config.minimum_page_size);
            let aligned_size = end_vaddr - base_vaddr;
            let name = format!("ELF:{}-{}", pd.name, seg_idx);
            let mr = SysMemoryRegion{
                name: name,
                size: aligned_size.into(),
                page_size: PageSize::Small,
                page_count: aligned_size / PageSize::Small as u64,
                phys_addr: Some(phys_addr_next)
            };
            phys_addr_next += aligned_size;

            let mp = SysMap {
                mr: mr.name.clone(),
                vaddr: base_vaddr,
                perms: perms,
                cached: true,
            };
            if let Some(extra_maps) = pd_extra_maps.get_mut(pd) {
                extra_maps.push(mp);
            } else {
                pd_extra_maps.insert(pd, vec![mp]);
            }

            // Add to extra_mrs at the end to avoid movement issues with the MR since it's used in
            // constructing the SysMap struct
            extra_mrs.push(mr);
        }
    }

    // TODO: this is a large copy here
    let mut all_mrs: Vec<&SysMemoryRegion> = Vec::with_capacity(system.memory_regions.len() + extra_mrs.len());
    for mr_set in [&system.memory_regions, &extra_mrs] {
        for mr in mr_set {
            all_mrs.push(mr);
        }
    }
    let all_mr_by_name: HashMap<&str, &SysMemoryRegion> = all_mrs.iter().map(|mr| (mr.name.as_str(), *mr)).collect();

    let mut system_invocations: Vec<Invocation> = Vec::new();
    let mut init_system = InitSystem::new(
        &kernel_config,
        root_cnode_cap,
        system_cap_address_mask,
        cap_slot,
        &mut kao,
        &kernel_boot_info,
        &mut system_invocations,
        &mut cap_address_names
    );

    init_system.reserve(invocation_table_allocations);

    // 3.1 Work out how many regular (non-fixed) page objects are required
    let mut small_page_names = Vec::new();
    let mut large_page_names = Vec::new();

    for pd in &system.protection_domains {
        let ipc_buffer_str = format!("Page({}): IPC Buffer PD={}", util::human_size_strict(PageSize::Small as u64), pd.name);
        small_page_names.push(ipc_buffer_str);
    }

    for mr in &all_mrs {
        if mr.phys_addr.is_some() {
            continue;
        }

        let page_size_human = util::human_size_strict(mr.page_size as u64);
        for idx in 0..mr.page_count {
            let page_str = format!("Page({}): MR={} #{}", page_size_human, mr.name, idx);
            match mr.page_size as PageSize {
                PageSize::Small => small_page_names.push(page_str),
                PageSize::Large => large_page_names.push(page_str),
            }
        }
    }

    // TODO: not sure if this HashMap approach is the most efficient?
    // TODO: in addition, mr_pages is a copy of page_objects.... yikes
    let mut page_objects: HashMap<PageSize, &Vec<KernelObject>> = HashMap::new();

    let large_page_objs = init_system.allocate_objects(ObjectType::LargePage, large_page_names, None);
    let small_page_objs = init_system.allocate_objects(ObjectType::SmallPage, small_page_names, None);

    // All the IPC buffers are the first to be allocated which is why this works
    let ipc_buffer_objs = &small_page_objs[..system.protection_domains.len()];

    page_objects.insert(PageSize::Large, &large_page_objs);
    page_objects.insert(PageSize::Small, &small_page_objs);

    let mut mr_pages: HashMap<&SysMemoryRegion, Vec<KernelObject>> = HashMap::new();
    let mut pg_idx: HashMap<PageSize, u64> = HashMap::new();

    // TODO: should do len of ipc_buffer_objects?
    pg_idx.insert(PageSize::Small, system.protection_domains.len() as u64);
    pg_idx.insert(PageSize::Large, 0);

    for mr in &all_mrs {
        if mr.phys_addr.is_some() {
            mr_pages.insert(mr, vec![]);
            continue;
        }
        // TODO: big mess, way to much going on with all these conversions etc
        let idx = *pg_idx.get(&mr.page_size).unwrap() as usize;
        mr_pages.insert(mr, page_objects[&mr.page_size][idx..idx + mr.page_count as usize].to_vec());
        // We assume that the entry for all possible page sizes already exists
        *pg_idx.get_mut(&mr.page_size).unwrap() += mr.page_count;
    }

    // 3.2 Now allocate all the fixed mRs

    // First we need to find all the requested pages and sorted them
    let mut fixed_pages = Vec::new();
    for mr in &all_mrs {
        if let Some(mut phys_addr) = mr.phys_addr {
            for _ in 0..mr.page_count {
                fixed_pages.push((phys_addr, mr));
                phys_addr += mr.page_bytes();
            }
        }
    }

    // Sort based on the starting physical address
    // TODO: check that this is correct
    fixed_pages.sort_by_key(|p| p.0);

    // FIXME: At this point we can recombine them into
    // groups to optimize allocation

    for (phys_addr, mr) in fixed_pages {
        let obj_type = match mr.page_size {
            PageSize::Small => ObjectType::SmallPage,
            PageSize::Large => ObjectType::LargePage,
        };

        let obj_type_name = format!("Page({})", util::human_size_strict(mr.page_size as u64));
        let name = format!("{}: MR={} @ {:x}", obj_type_name, mr.name, phys_addr);
        let page = init_system.allocate_fixed_objects(phys_addr, obj_type, 1, vec![name]);
        assert!(page.len() == 1);
        // TODO: is this extend just doing a clone?
        mr_pages.get_mut(mr).unwrap().extend(page);
    }

    let tcb_names: Vec<String> = system.protection_domains.iter().map(|pd| format!("TCB: PD={}", pd.name)).collect();
    let tcb_objs = init_system.allocate_objects(ObjectType::Tcb, tcb_names, None);
    let tcb_caps: Vec<u64> = tcb_objs.iter().map(|tcb| tcb.cap_addr).collect();

    let sched_context_names = system.protection_domains.iter().map(|pd| format!("SchedContext: PD={}", pd.name)).collect();
    let sched_context_objs = init_system.allocate_objects(ObjectType::SchedContext, sched_context_names, Some(PD_SCHEDCONTEXT_SIZE));
    let sched_context_caps: Vec<u64> = sched_context_objs.iter().map(|sc| sc.cap_addr).collect();

    let pp_protection_domains: Vec<&ProtectionDomain> = system.protection_domains.iter().filter(|pd| pd.pp).collect();

    // TODO: this logic could be a bit cleaner...
    let pd_endpoint_names: Vec<String> = pp_protection_domains.iter().map(|pd| format!("EP: PD={}", pd.name)).collect();
    let endpoint_names = [vec![format!("EP: Monitor Fault")], pd_endpoint_names].concat();

    let pd_reply_names: Vec<String> = system.protection_domains.iter().map(|pd| format!("Reply: PD={}", pd.name)).collect();
    let reply_names = [vec![format!("Reply: Monitor")], pd_reply_names].concat();
    let reply_objs = init_system.allocate_objects(ObjectType::Reply, reply_names, None);
    let reply_obj = &reply_objs[0];
    // FIXME: Probably only need reply objects for PPs
    let pd_reply_objs = &reply_objs[1..];
    let endpoint_objs = init_system.allocate_objects(ObjectType::Endpoint, endpoint_names, None);
    let fault_ep_endpoint_object = &endpoint_objs[0];
    let mut pp_ep_endpoint_objs: HashMap<&ProtectionDomain, &KernelObject> = HashMap::with_capacity(pp_protection_domains.len());
    for (i, pd) in pp_protection_domains.iter().enumerate() {
        // Because the first reply object is for the monitor, we map from index 1 of endpoint_objs
        pp_ep_endpoint_objs.insert(pd, &endpoint_objs[1..][i]);
    }

    let notification_names = system.protection_domains.iter().map(|pd| format!("Notification: PD={}", pd.name)).collect();
    let notification_objs = init_system.allocate_objects(ObjectType::Notification, notification_names, None);
    let notification_caps = notification_objs.iter().map(|ntfn| ntfn.cap_addr).collect();
    // TODO: notification_objs_by_pd is only really used when processing channels, we may be able to just
    // remove this altogether and go off indexes instead
    let mut notification_objs_by_pd: HashMap<&ProtectionDomain, &KernelObject> = HashMap::with_capacity(notification_objs.len());
    for (i, pd) in system.protection_domains.iter().enumerate() {
        notification_objs_by_pd.insert(pd, &notification_objs[i]);
    }

    // Determine number of upper directory / directory / page table objects required
    //
    // Upper directory (level 3 table) is based on how many 512 GiB parts of the address
    // space is covered (normally just 1!).
    //
    // Page directory (level 2 table) is based on how many 1,024 MiB parts of
    // the address space is covered
    //
    // Page table (level 3 table) is based on how many 2 MiB parts of the
    // address space is covered (excluding any 2MiB regions covered by large
    // pages).
    let mut uds: Vec<(usize, u64)> = Vec::new();
    let mut ds: Vec<(usize, u64)> = Vec::new();
    let mut pts: Vec<(usize, u64)> = Vec::new();
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        let (ipc_buffer_vaddr, _) = pd_elf_files[pd].find_symbol(SYMBOL_IPC_BUFFER);
        let mut upper_directory_vaddrs = HashSet::new();
        let mut directory_vaddrs = HashSet::new();
        let mut page_table_vaddrs = HashSet::new();

        // For each page, in each map determine we determine
        // which upper directory, directory and page table is resides
        // in, and then page sure this is set
        let mut vaddrs = vec![(ipc_buffer_vaddr, PageSize::Small)];
        for map_set in [&pd.maps, &pd_extra_maps[pd]] {
            for map in map_set {
                let mr = all_mr_by_name[map.mr.as_str()];
                let mut vaddr = map.vaddr;
                for _ in 0..mr.page_count {
                    vaddrs.push((vaddr, mr.page_size));
                    vaddr += mr.page_bytes();
                }
            }
        }

        for (vaddr, page_size) in vaddrs {
            upper_directory_vaddrs.insert(util::mask_bits(vaddr, 12 + 9 + 9 + 9));
            directory_vaddrs.insert(util::mask_bits(vaddr, 12 + 9 + 9));
            if page_size == PageSize::Small {
                page_table_vaddrs.insert(util::mask_bits(vaddr, 12 + 9));
            }
        }

        // TODO: find out if we can simplify....
        let pd_uds: Vec<(usize, u64)> = upper_directory_vaddrs.into_iter().map(|vaddr| (pd_idx, vaddr)).collect();
        uds.extend(pd_uds);
        let pd_ds: Vec<(usize, u64)> = directory_vaddrs.into_iter().map(|vaddr| (pd_idx, vaddr)).collect();
        ds.extend(pd_ds);
        let pd_pts: Vec<(usize, u64)> = page_table_vaddrs.into_iter().map(|vaddr| (pd_idx, vaddr)).collect();
        pts.extend(pd_pts);
    }

    let pd_names: Vec<&str> = system.protection_domains.iter().map(|pd| pd.name.as_str()).collect();

    let vspace_names: Vec<String> = system.protection_domains.iter().map(|pd| format!("VSpace: PD={}", pd.name)).collect();
    let vspace_objs = init_system.allocate_objects(ObjectType::VSpace, vspace_names, None);

    let ud_names = uds.iter().map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr)).collect();
    let ud_objs = init_system.allocate_objects(ObjectType::PageTable, ud_names, None);

    let d_names = ds.iter().map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr)).collect();
    let d_objs = init_system.allocate_objects(ObjectType::PageTable, d_names, None);

    let pt_names = pts.iter().map(|(pd_idx, vaddr)| format!("PageTable: PD={} VADDR=0x{:x}", pd_names[*pd_idx], vaddr)).collect();
    let pt_objs = init_system.allocate_objects(ObjectType::PageTable, pt_names, None);

    uds.sort_by_key(|ud| ud.1);
    ds.sort_by_key(|d| d.1);
    pts.sort_by_key(|pt| pt.1);

    // Create CNodes - all CNode objects are the same size: 128 slots.
    let cnode_names: Vec<String> = system.protection_domains.iter().map(|pd| format!("CNode: PD={}", pd.name)).collect();
    let cnode_objs = init_system.allocate_objects(ObjectType::CNode, cnode_names, Some(PD_CAP_SIZE));
    let mut cnode_objs_by_pd: HashMap<&ProtectionDomain, &KernelObject> = HashMap::with_capacity(system.protection_domains.len());
    for (i, pd) in system.protection_domains.iter().enumerate() {
        cnode_objs_by_pd.insert(pd, &cnode_objs[i]);
    }

    let mut cap_slot = init_system.cap_slot;
    let kernel_objects = init_system.objects.clone();

    // Create all the necessary interrupt handler objects. These aren't
    // created through retype though!
    let mut irq_cap_addresses: HashMap<&ProtectionDomain, Vec<u64>> = HashMap::new();
    for pd in &system.protection_domains {
        irq_cap_addresses.insert(pd, vec![]);
        for sysirq in &pd.irqs {
            let cap_address = system_cap_address_mask | cap_slot;
            system_invocations.push(Invocation::new(InvocationArgs::IrqControlGetTrigger{
                irq_control: IRQ_CONTROL_CAP_ADDRESS,
                irq: sysirq.irq,
                trigger: sysirq.trigger,
                dest_root: root_cnode_cap,
                dest_index: cap_address,
                dest_depth: kernel_config.cap_address_bits,
            }));

            cap_slot += 1;
            cap_address_names.insert(cap_address, format!("IRQ Handler: irq={}", sysirq.irq));
            irq_cap_addresses.get_mut(pd).unwrap().push(cap_address);
        }
    }

    // This has to be done prior to minting!
    let mut asid_invocation = Invocation::new(InvocationArgs::AsidPoolAssign {
        asid_pool: INIT_ASID_POOL_CAP_ADDRESS,
        vspace: vspace_objs[0].cap_addr,
    });
    asid_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::AsidPoolAssign{
        asid_pool: 0,
        vspace: 1,
    });
    system_invocations.push(asid_invocation);

    // Create copies of all caps required via minting.

    // Mint copies of required pages, while also determing what's required
    // for later mapping
    let mut page_descriptors = Vec::new();
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        for map_set in [&pd.maps, &pd_extra_maps[pd]] {
            for mp in map_set {
                let mr = all_mr_by_name[mp.mr.as_str()];
                let mut rights: u64 = Rights::None as u64;
                let mut attrs = SEL4_ARM_PARITY_ENABLED;
                // TODO: this is a bit awkward
                if mp.perms & SysMapPerms::Read as u8 != 0 {
                    rights |= Rights::Read as u64;
                }
                if mp.perms & SysMapPerms::Write as u8 != 0 {
                    rights |= Rights::Write as u64;
                }
                if mp.perms & SysMapPerms::Execute as u8 == 0 {
                    attrs |= SEL4_ARM_EXECUTE_NEVER;
                }
                if mp.cached {
                    attrs |= SEL4_ARM_PAGE_CACHEABLE;
                }

                assert!(mr_pages[mr].len() > 0);
                assert!(util::objects_adjacent(&mr_pages[mr]));

                let mut invocation = Invocation::new(InvocationArgs::CnodeMint{
                    cnode: system_cnode_cap,
                    dest_index: cap_slot,
                    dest_depth: system_cnode_bits,
                    src_root: root_cnode_cap,
                    src_obj: mr_pages[mr][0].cap_addr,
                    src_depth: kernel_config.cap_address_bits,
                    rights: rights,
                    badge: 0,
                });
                invocation.repeat(mr_pages[mr].len() as u64, InvocationArgs::CnodeMint{
                    cnode: 0,
                    dest_index: 1,
                    dest_depth: 0,
                    src_root: 0,
                    src_obj: 1,
                    src_depth: 0,
                    rights: 0,
                    badge: 0,
                });
                system_invocations.push(invocation);

                page_descriptors.push((
                    system_cap_address_mask | cap_slot,
                    pd_idx,
                    mp.vaddr,
                    rights,
                    attrs,
                    mr_pages[mr].len() as u64,
                    mr.page_bytes()
                ));

                for idx in 0..mr_pages[mr].len() {
                    cap_address_names.insert(
                        system_cap_address_mask | (cap_slot + idx as u64),
                        format!("{} (derived)", cap_address_names.get(&(mr_pages[mr][0].cap_addr + idx as u64)).unwrap())
                    );
                }

                cap_slot += mr_pages[mr].len() as u64;
            }
        }
    }

    let mut badged_irq_caps: HashMap<&ProtectionDomain, Vec<u64>> = HashMap::new();
    for (notification_obj, pd) in zip(&notification_objs, &system.protection_domains) {
        badged_irq_caps.insert(pd, vec![]);
        for sysirq in &pd.irqs {
            let badge = 1 << sysirq.id;
            let badged_cap_address = system_cap_address_mask | cap_slot;
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint{
                cnode: system_cnode_cap,
                dest_index: cap_slot,
                dest_depth: system_cnode_bits,
                src_root: root_cnode_cap,
                src_obj: notification_obj.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64,
                badge: badge,
            }));
            let badged_name = format!("{} (badge=0x{:x}", cap_address_names[&notification_obj.cap_addr], badge);
            cap_address_names.insert(badged_cap_address, badged_name);
            badged_irq_caps.get_mut(pd).unwrap().push(badged_cap_address);
            cap_slot += 1;
        }
    }

    let mut invocation = Invocation::new(InvocationArgs::CnodeMint{
        cnode: system_cnode_cap,
        dest_index: cap_slot,
        dest_depth: system_cnode_bits,
        src_root: root_cnode_cap,
        src_obj: fault_ep_endpoint_object.cap_addr,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: 1,
    });
    invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::CnodeMint{
        cnode: 0,
        dest_index: 1,
        dest_depth: 0,
        src_root: 0,
        src_obj: 0,
        src_depth: 0,
        rights: 0,
        badge: 1,
    });
    system_invocations.push(invocation);

    let badged_fault_ep = system_cap_address_mask | cap_slot;
    cap_slot += system.protection_domains.len() as u64;

    let final_cap_slot = cap_slot;

    // Minting in the address space
    for (idx, pd) in system.protection_domains.iter().enumerate() {
        let obj = if pd.pp {
            pp_ep_endpoint_objs[pd]
        } else {
            &notification_objs[idx]
        };
        assert!(INPUT_CAP_IDX < PD_CAP_SIZE);

        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: cnode_objs[idx].cap_addr,
            dest_index: INPUT_CAP_IDX,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,
            badge: 0,
        }));
    }

    // TODO: compile time asserts for these kind of asserts?

    // Mint access to the reply cap
    assert!(REPLY_CAP_IDX < PD_CAP_SIZE);
    let mut reply_mint_invocation = Invocation::new(InvocationArgs::CnodeMint {
        cnode: cnode_objs[0].cap_addr,
        dest_index: REPLY_CAP_IDX,
        dest_depth: PD_CAP_BITS,
        src_root: root_cnode_cap,
        src_obj: pd_reply_objs[0].cap_addr,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: 1,
    });
    reply_mint_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::CnodeMint {
        cnode: 1,
        dest_index: 0,
        dest_depth: 0,
        src_root: 0,
        src_obj: 1,
        src_depth: 0,
        rights: 0,
        badge: 0,
    });
    system_invocations.push(reply_mint_invocation);

    // Mint access to the VSpace cap
    assert!(VSPACE_CAP_IDX < PD_CAP_SIZE);
    let mut vspace_mint_invocation = Invocation::new(InvocationArgs::CnodeMint {
        cnode: cnode_objs[0].cap_addr,
        dest_index: VSPACE_CAP_IDX,
        dest_depth: PD_CAP_BITS,
        src_root: root_cnode_cap,
        src_obj: vspace_objs[0].cap_addr,
        src_depth: kernel_config.cap_address_bits,
        rights: Rights::All as u64,
        badge: 0,
    });
    vspace_mint_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::CnodeMint {
        cnode: 1,
        dest_index: 0,
        dest_depth: 0,
        src_root: 0,
        src_obj: 1,
        src_depth: 0,
        rights: 0,
        badge: 0,
    });
    system_invocations.push(vspace_mint_invocation);

    // Mint access to interrupt handlers in the PD CSpace
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        for (sysirq, irq_cap_address) in zip(&pd.irqs, &irq_cap_addresses[pd]) {
            let cap_idx = BASE_IRQ_CAP + sysirq.id;
            assert!(cap_idx < PD_CAP_SIZE);
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_objs[pd_idx].cap_addr,
                dest_index: cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: *irq_cap_address,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64,
                badge: 0,
            }));
        }
    }

    for cc in &system.channels {
        let pd_a = cc.pd_a;
        let pd_b = cc.pd_b;
        let pd_a_cnode_obj = cnode_objs_by_pd[pd_a];
        let pd_b_cnode_obj = cnode_objs_by_pd[pd_b];
        let pd_a_notification_obj = notification_objs_by_pd[pd_a];
        let pd_b_notification_obj = notification_objs_by_pd[pd_b];

        // Set up the notification caps
        let pd_a_cap_idx = BASE_OUTPUT_NOTIFICATION_CAP + cc.id_a;
        let pd_a_badge = 1 << cc.id_b;
        assert!(pd_a_cap_idx < PD_CAP_SIZE);
        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: pd_a_cnode_obj.cap_addr,
            dest_index: pd_a_cap_idx,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: pd_b_notification_obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,  // FIXME: Check rights
            badge: pd_a_badge
        }));

        let pd_b_cap_idx = BASE_OUTPUT_NOTIFICATION_CAP + cc.id_b;
        let pd_b_badge = 1 << cc.id_a;
        assert!(pd_b_cap_idx < PD_CAP_SIZE);
        system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
            cnode: pd_b_cnode_obj.cap_addr,
            dest_index: pd_b_cap_idx,
            dest_depth: PD_CAP_BITS,
            src_root: root_cnode_cap,
            src_obj: pd_a_notification_obj.cap_addr,
            src_depth: kernel_config.cap_address_bits,
            rights: Rights::All as u64,  // FIXME: Check rights
            badge: pd_b_badge
        }));

        // Set up the endpoint caps
        if pd_b.pp {
            let pd_a_cap_idx = BASE_OUTPUT_NOTIFICATION_CAP + cc.id_a;
            let pd_a_badge = (1 << 63) | cc.id_b;
            let pd_b_endpoint_obj = pp_ep_endpoint_objs[pd_b];
            assert!(pd_a_cap_idx < PD_CAP_BITS);

            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: pd_a_cnode_obj.cap_addr,
                dest_index: pd_a_cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: pd_b_endpoint_obj.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights
                badge: pd_a_badge,
            }));
        }

        if pd_a.pp {
            let pd_b_cap_idx = BASE_OUTPUT_ENDPOINT_CAP + cc.id_b;
            let pd_b_badge = (1 << 63) | cc.id_a;
            let pd_a_endpoint_obj = pp_ep_endpoint_objs[pd_a];
            assert!(pd_b_cap_idx < PD_CAP_SIZE);

            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: pd_b_cnode_obj.cap_addr,
                dest_index: pd_b_cap_idx,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: pd_a_endpoint_obj.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights
                badge: pd_b_badge,
            }));
        }
    }

    // Mint a cap between monitor and passive PDs.
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        if pd.passive {
            let cnode_obj = &cnode_objs[pd_idx];
            system_invocations.push(Invocation::new(InvocationArgs::CnodeMint {
                cnode: cnode_obj.cap_addr,
                dest_index: MONITOR_EP_CAP_IDX,
                dest_depth: PD_CAP_BITS,
                src_root: root_cnode_cap,
                src_obj: fault_ep_endpoint_object.cap_addr,
                src_depth: kernel_config.cap_address_bits,
                rights: Rights::All as u64, // FIXME: Check rights
                // Badge needs to start at 1
                badge: pd_idx as u64 + 1,
            }));
        }
    }

    // All minting is complete at this point

    // Associate badges
    // FIXME: This could use repeat
    for pd in &system.protection_domains {
        for (irq_cap_address, badged_notification_cap_address) in zip(&irq_cap_addresses[pd], &badged_irq_caps[pd]) {
            system_invocations.push(Invocation::new(InvocationArgs::IrqHandlerSetNotification {
                irq_handler: *irq_cap_address,
                notification: *badged_notification_cap_address,
            }));
        }
    }

    // Initialise the VSpaces -- assign them all the the initial asid pool.
    for (descriptors, objects) in [(uds, ud_objs), (ds, d_objs), (pts, pt_objs)] {
        for ((pd_idx, vaddr), obj) in zip(descriptors, objects) {
            system_invocations.push(Invocation::new(InvocationArgs::PageTableMap{
                page_table: obj.cap_addr,
                vspace: vspace_objs[pd_idx].cap_addr,
                vaddr: vaddr,
                attr: SEL4_ARM_DEFAULT_VMATTRIBUTES,
            }));
        }
    }

    // Now map all the pages
    for (page_cap_address, pd_idx, vaddr, rights, attr, count, vaddr_incr) in page_descriptors {
        let mut invocation = Invocation::new(InvocationArgs::PageMap {
            page: page_cap_address,
            vspace: vspace_objs[pd_idx].cap_addr,
            vaddr,
            rights,
            attr,
        });
        invocation.repeat(count, InvocationArgs::PageMap {
            page: 1,
            vspace: 0,
            vaddr: vaddr_incr,
            rights: 0,
            attr: 0,
        });
        system_invocations.push(invocation);
    }

    // And, finally, map all the IPC buffers
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        let (vaddr, _) = pd_elf_files[pd].find_symbol(SYMBOL_IPC_BUFFER);
        system_invocations.push(Invocation::new(InvocationArgs::PageMap {
            page: ipc_buffer_objs[pd_idx].cap_addr,
            vspace: vspace_objs[pd_idx].cap_addr,
            vaddr,
            rights: Rights::Read as u64 | Rights::Write as u64,
            attr: SEL4_ARM_DEFAULT_VMATTRIBUTES | SEL4_ARM_EXECUTE_NEVER,
        }));
    }

    // Initialise the TCBs

    // Set the scheduling parameters
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        system_invocations.push(Invocation::new(InvocationArgs::SchedControlConfigureFlags {
            sched_control: kernel_boot_info.sched_control_cap,
            sched_context: sched_context_objs[pd_idx].cap_addr,
            budget: pd.budget as u64,
            period: pd.period as u64,
            extra_refills: 0,
            badge: 0x100 + pd_idx as u64,
            flags: 0,
        }));
    }

    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        system_invocations.push(Invocation::new(InvocationArgs::TcbSetSchedParams {
            tcb: tcb_objs[pd_idx].cap_addr,
            authority: INIT_TCB_CAP_ADDRESS,
            mcp: pd.priority as u64,
            priority: pd.priority as u64,
            sched_context: sched_context_objs[pd_idx].cap_addr,
            fault_ep: fault_ep_endpoint_object.cap_addr,
        }));
    }

    // Set VSpace and CSpace
    let mut set_space_invocation = Invocation::new(InvocationArgs::TcbSetSpace {
        tcb: tcb_objs[0].cap_addr,
        fault_ep: badged_fault_ep,
        cspace_root: cnode_objs[0].cap_addr,
        cspace_root_data: kernel_config.cap_address_bits - PD_CAP_BITS,
        vspace_root: vspace_objs[0].cap_addr,
        vspace_root_data: 0,
    });
    set_space_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::TcbSetSpace {
        tcb: 1,
        fault_ep: 1,
        cspace_root: 1,
        cspace_root_data: 0,
        vspace_root: 1,
        vspace_root_data: 0,
    });
    system_invocations.push(set_space_invocation);

    // Set IPC buffer
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        let (ipc_buffer_vaddr, _) = pd_elf_files[pd].find_symbol(SYMBOL_IPC_BUFFER);
        system_invocations.push(Invocation::new(InvocationArgs::TcbSetIpcBuffer {
            tcb: tcb_objs[pd_idx].cap_addr,
            buffer: ipc_buffer_vaddr,
            buffer_frame: ipc_buffer_objs[pd_idx].cap_addr,
        }));
    }

    // Set TCB registers (we only set the entry point)
    for (pd_idx, pd) in system.protection_domains.iter().enumerate() {
        let mut regs = Aarch64Regs::new();
        regs.pc = pd_elf_files[pd].entry;

        system_invocations.push(Invocation::new(InvocationArgs::TcbWriteRegisters {
            tcb: tcb_objs[pd_idx].cap_addr,
            resume: false,
            // There are no arch-dependent flags to set
            arch_flags: 0,
            count: regs.count(),
            regs: regs,
        }));
    }

    // Bind the notification object
    let mut bind_ntfn_invocation = Invocation::new(InvocationArgs::TcbBindNotification{
        tcb: tcb_objs[0].cap_addr,
        notification: notification_objs[0].cap_addr,
    });
    bind_ntfn_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::TcbBindNotification {
        tcb: 1,
        notification: 1,
    });
    system_invocations.push(bind_ntfn_invocation);

    // Resume (start) all the threads
    let mut resume_invocation = Invocation::new(InvocationArgs::TcbResume{
        tcb: tcb_objs[0].cap_addr,
    });
    resume_invocation.repeat(system.protection_domains.len() as u64, InvocationArgs::TcbResume {
        tcb: 1,
    });
    system_invocations.push(resume_invocation);

    // All of the objects are created at this point; we don't need both
    // the allocators from here.

    // And now we are finally done. We have all the invocations

    // TODO: get invocation data
    let mut system_invocation_data: Vec<u8> = Vec::new();
    for system_invocation in &system_invocations {
        system_invocation.add_raw_invocation(&mut system_invocation_data);
    }

    for pd in &system.protection_domains {
        let elf = pd_elf_files.get_mut(pd).unwrap();
        elf.write_symbol("microkit_name", pd.name.as_bytes());
        elf.write_symbol("passive", &[pd.passive as u8]);
    }

    for pd in &system.protection_domains {
        for setvar in &pd.setvars {
            let value;
            if let Some(region_paddr) = &setvar.region_paddr {
                let mr = system.memory_regions.iter()
                                              .find(|mr| mr.name == *region_paddr)
                                              .expect(format!("Cannot find region: {}", region_paddr).as_str());
                value = mr_pages[mr][0].phys_addr;
            } else if let Some(vaddr) = setvar.vaddr {
                value = vaddr;
            } else {
                panic!("Unable to patch variable '{}' in protection domain '{}': variable not found.", setvar.symbol, pd.name);
            }

            // We assume that all the architectures we are dealing with are little-endian
            pd_elf_files.get_mut(pd).unwrap().write_symbol(&setvar.symbol, &value.to_le_bytes());
        }
    }

    BuiltSystem {
        number_of_system_caps: final_cap_slot,
        invocation_data_size: system_invocation_data.len() as u64,
        bootstrap_invocations: bootstrap_invocations,
        system_invocations: system_invocations,
        kernel_boot_info: kernel_boot_info,
        reserved_region,
        fault_ep_cap_address: fault_ep_endpoint_object.cap_addr,
        reply_cap_address: reply_obj.cap_addr,
        cap_lookup: cap_address_names,
        tcb_caps,
        sched_caps: sched_context_caps,
        ntfn_caps: notification_caps,
        regions,
        kernel_objects,
        initial_task_phys_region,
        initial_task_virt_region,
    }
}

fn main() {
    let arg_sdf_path = std::env::args().nth(1).expect("no system description path given");
    let xml: String = fs::read_to_string(arg_sdf_path).unwrap();
    let system = parse(&xml);

    let kernel_config = KernelConfig {
        word_size: 64,
        minimum_page_size: 4096,
        paddr_user_device_top: 1 << 40,
        kernel_frame_size: 1 << 12,
        init_cnode_bits: 12,
        cap_address_bits: 64,
        fan_out_limit: 256,
    };

    let monitor_config = MonitorConfig {
        untyped_info_symbol_name: "untyped_info",
        bootstrap_invocation_count_symbol_name: "bootstrap_invocation_count",
        bootstrap_invocation_data_symbol_name: "bootstrap_invocation_data",
        system_invocation_count_symbol_name: "system_invocation_count",
    };

    let monitor_elf_path = "testing/monitor.elf";
    let loader_elf_path = "testing/loader.elf";

    // TODO: need to test what happens when these paths do not exist
    // and do error checking.
    let kernel_elf = ElfFile::from_path(Path::new("testing/sel4.elf"));
    let mut monitor_elf = ElfFile::from_path(Path::new(monitor_elf_path));

    if monitor_elf.segments.len() > 1 {
        panic!("Monitor ({}) has {} segments, it must only have one", monitor_elf_path, monitor_elf.segments.len());
    }

    let search_paths = vec!["testing"];

    // TODO: do not hardcode
    // let board = "qemu_virt_aarch64";
    // let config = "debug";

    let mut invocation_table_size = kernel_config.minimum_page_size;
    let mut system_cnode_size = 2;

    let mut built_system;
    loop {
        built_system = build_system(
            &kernel_config,
            &kernel_elf,
            &monitor_elf,
            &system,
            invocation_table_size,
            system_cnode_size,
            &search_paths
        );
        println!("BUILT: system_cnode_size={}, built_system.number_of_system_caps={} invocation_table_size={} built_system.invocation_data_size={}",
                 system_cnode_size, built_system.number_of_system_caps, invocation_table_size, built_system.invocation_data_size);

        if built_system.number_of_system_caps <= system_cnode_size &&
           built_system.invocation_data_size <= invocation_table_size {
            break;
        }

        // Recalculate the sizes for the next iteration
        let new_invocation_table_size = util::round_up(built_system.invocation_data_size, kernel_config.minimum_page_size);
        // TODO: check that the semantics of the Python version
        let new_system_cnode_size = 2_u32.pow(built_system.number_of_system_caps.next_power_of_two().ilog2());

        invocation_table_size = max(invocation_table_size, new_invocation_table_size) as u64;
        system_cnode_size = max(system_cnode_size, new_system_cnode_size as u64) as u64;
    }

    // At this point we just need to patch the files (in memory) and write out the final image.

    // A: The monitor

    // A.1: As part of emulated boot we determined exactly how the kernel would
    // create untyped objects. Throught testing we know that this matches, but
    // we could have a bug, or the kernel could change. It that happens we are
    // in a bad spot! Things will break. So we write out this information so that
    // the monitor can double check this at run time.
    let (_, untyped_info_size) = monitor_elf.find_symbol(monitor_config.untyped_info_symbol_name);
    let max_untyped_objects = monitor_config.max_untyped_objects(untyped_info_size);
    if built_system.kernel_boot_info.untyped_objects.len() as u64 > max_untyped_objects {
        // TODO: comma separator missing in panic
        panic!("Too many untyped objects: monitor ({}) supports {} regions. System has {} objects.",
              monitor_elf_path, max_untyped_objects, built_system.kernel_boot_info.untyped_objects.len());
    }

    let untyped_info_header = MonitorUntypedInfoHeader64 {
        cap_start: built_system.kernel_boot_info.untyped_objects[0].cap,
        cap_end: built_system.kernel_boot_info.untyped_objects.last().unwrap().cap + 1,
    };
    let untyped_info_object_data: Vec<MonitorRegion64> = built_system.kernel_boot_info.untyped_objects
                                                        .iter()
                                                        .map(|ut| MonitorRegion64 {
                                                            paddr: ut.base(),
                                                            size_bits: ut.size_bits(),
                                                            is_device: ut.is_device as u64,
                                                        })
                                                        .collect();
    let mut untyped_info_data: Vec<u8> = Vec::from(unsafe { struct_to_bytes(&untyped_info_header) });
    for o in &untyped_info_object_data {
        untyped_info_data.extend(unsafe { struct_to_bytes(o) });
    }
    monitor_elf.write_symbol(monitor_config.untyped_info_symbol_name, &untyped_info_data);

    let bootstrap_invocation_data: Vec<u8> = Vec::new();
    let system_invocation_data: Vec<u8> = Vec::new();

    monitor_elf.write_symbol(monitor_config.bootstrap_invocation_count_symbol_name, &built_system.bootstrap_invocations.len().to_le_bytes());
    monitor_elf.write_symbol(monitor_config.system_invocation_count_symbol_name, &built_system.system_invocations.len().to_le_bytes());
    monitor_elf.write_symbol(monitor_config.bootstrap_invocation_data_symbol_name, &bootstrap_invocation_data);

    // TODO: sort out invocation data

    let tcb_cap_bytes: Vec<u8> = built_system.tcb_caps.iter().flat_map(|cap| cap.to_le_bytes()).collect();
    let sched_cap_bytes: Vec<u8> = built_system.sched_caps.iter().flat_map(|cap| cap.to_le_bytes()).collect();
    let ntfn_cap_bytes: Vec<u8> = built_system.ntfn_caps.iter().flat_map(|cap| cap.to_le_bytes()).collect();

    monitor_elf.write_symbol("fault_ep", &built_system.fault_ep_cap_address.to_le_bytes());
    monitor_elf.write_symbol("reply", &built_system.reply_cap_address.to_le_bytes());
    monitor_elf.write_symbol("tcbs", &tcb_cap_bytes);
    monitor_elf.write_symbol("scheduling_contexts", &sched_cap_bytes);
    monitor_elf.write_symbol("notification_caps", &ntfn_cap_bytes);
    // TODO: write out names
    let mut pd_names_bytes = vec![0; MAX_PDS * PD_MAX_NAME_LENGTH];
    for (i, pd) in system.protection_domains.iter().enumerate() {
        // The monitor will index into the array of PD names based on the badge, which
        // starts at 1 and hence we cannot use the 0th entry in the array.
        let name = pd.name.as_bytes();
        let start = (i + 1) * PD_MAX_NAME_LENGTH;
        // Here instead of giving an error we simply take the minimum of the PD's name
        // and how large of a name we can encode
        let name_length = min(name.len(), PD_MAX_NAME_LENGTH);
        let end = (i + 1) * PD_MAX_NAME_LENGTH + name_length;
        pd_names_bytes[start..end].copy_from_slice(&name);
    }

    // Generate the report
    let report_path = "report.txt";
    let report = match std::fs::File::create(report_path) {
        Ok(file) => file,
        Err(e) => panic!("Could not create report file '{}': {}", report_path, e),
    };

    let mut report_buf = BufWriter::new(report);
    _ = report_buf.write(b"# Kernel Boot Info\n\n");

    // TODO: this is a lot of error ignoring...
    // TODO: need to match formatting with Python
    _ = writeln!(&mut report_buf, "    # of fixed caps     : {:>8}", built_system.kernel_boot_info.fixed_cap_count);
    _ = writeln!(&mut report_buf, "    # of page table caps: {:>8}", built_system.kernel_boot_info.paging_cap_count);
    _ = writeln!(&mut report_buf, "    # of page caps      : {:>8}", built_system.kernel_boot_info.page_cap_count);
    _ = writeln!(&mut report_buf, "    # of untyped objects: {:>8}", built_system.kernel_boot_info.untyped_objects.len());
    _ = writeln!(&mut report_buf, "\n# Loader Regions\n");
    for region in built_system.regions {
        _ = writeln!(&mut report_buf, "       {}", region);
    }
    _ = writeln!(&mut report_buf, "\n# Monitor (Initial Task) Info\n");
    _ = writeln!(&mut report_buf, "     virtual memory : {}", built_system.initial_task_virt_region);
    _ = writeln!(&mut report_buf, "     physical memory: {}", built_system.initial_task_phys_region);
    _ = writeln!(&mut report_buf, "\n# Allocated Kernel Objects Summary\n");
    _ = writeln!(&mut report_buf, "     # of allocated objects: {}", built_system.kernel_objects.len());
    _ = writeln!(&mut report_buf, "\n# Bootstrap Kernel Invocations Summary\n");
    _ = writeln!(&mut report_buf, "     # of invocations   : {:>10}", built_system.bootstrap_invocations.len());
    _ = writeln!(&mut report_buf, "     size of invocations: {:>10}", bootstrap_invocation_data.len());
    _ = writeln!(&mut report_buf, "\n# System Kernel Invocations Summary\n");
    _ = writeln!(&mut report_buf, "     # of invocations   : {:>10}", built_system.system_invocations.len());
    _ = writeln!(&mut report_buf, "     size of invocations: {:>10}", system_invocation_data.len());
    _ = writeln!(&mut report_buf, "\n# Allocated Kernel Objects Detail\n");
    for ko in &built_system.kernel_objects {
        // TODO: don't use debug display for object type
        // TODO: would be good to print both the number for the object type and the string
        _ = writeln!(&mut report_buf, "    {:<50} {} cap_addr={:x} phys_addr={:x}", ko.name, ko.object_type as u64, ko.cap_addr, ko.phys_addr);
    }
    _ = writeln!(&mut report_buf, "\n# Bootstrap Kernel Invocations Detail\n");
    for (i, invocation) in built_system.bootstrap_invocations.iter().enumerate() {
        _ = write!(&mut report_buf, "    0x{:04x} ", i);
        invocation.report_fmt(&mut report_buf, &built_system.cap_lookup);
    }
    _ = writeln!(&mut report_buf, "\n# System Kernel Invocations Detail\n");
    for (i, invocation) in built_system.system_invocations.iter().enumerate() {
        _ = write!(&mut report_buf, "    0x{:04x} ", i);
        invocation.report_fmt(&mut report_buf, &built_system.cap_lookup);
    }

    report_buf.flush().unwrap();

    let loader = Loader::new(
        &Path::new(loader_elf_path),
        &kernel_elf,
        &monitor_elf,
        Some(built_system.initial_task_phys_region.base),
        built_system.reserved_region,
        // TODO: this is wrong, we need all the regions not just these
        vec![(built_system.reserved_region.base, &system_invocation_data)]
    );
    loader.write_image(&Path::new("testing/loader.img"))
}
