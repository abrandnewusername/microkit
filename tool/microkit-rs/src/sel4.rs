#[repr(u64)]
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub enum ObjectType {
    Untyped = 0,
    Tcb = 1,
    Endpoint = 2,
    Notification = 3,
    CNode = 4,
    SchedContext = 5,
    Reply = 6,
    HugePage = 7,
    VSpace = 8,
    SmallPage = 9,
    LargePage = 10,
    PageTable = 11,
}

impl ObjectType {
    pub fn fixed_size(&self) -> Option<u64> {
        match self {
            ObjectType::Tcb => Some(OBJECT_SIZE_TCB),
            ObjectType::Endpoint => Some(OBJECT_SIZE_ENDPOINT),
            ObjectType::Notification => Some(OBJECT_SIZE_NOTIFICATION),
            ObjectType::Reply => Some(OBJECT_SIZE_REPLY),
            ObjectType::VSpace => Some(OBJECT_SIZE_VSPACE),
            ObjectType::PageTable => Some(OBJECT_SIZE_PAGE_TABLE),
            ObjectType::LargePage => Some(OBJECT_SIZE_LARGE_PAGE),
            ObjectType::SmallPage => Some(OBJECT_SIZE_SMALL_PAGE),
            _ => None
        }
    }
}

#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum PageSize {
    Small = 0x1000,
    Large = 0x200_000,
}

impl From<u64> for PageSize {
    fn from(item: u64) -> PageSize {
        match item {
            0x1000 => PageSize::Small,
            0x200_000 => PageSize::Large,
            _ => panic!("Unknown page size {:x}", item),
        }
    }
}

pub const OBJECT_SIZE_TCB: u64 = 1 << 11;
pub const OBJECT_SIZE_ENDPOINT: u64 = 1 << 4;
pub const OBJECT_SIZE_NOTIFICATION: u64 = 1 << 6;
pub const OBJECT_SIZE_REPLY: u64 = 1 << 5;
pub const OBJECT_SIZE_PAGE_TABLE: u64 = 1 << 12;
pub const OBJECT_SIZE_LARGE_PAGE: u64 = 2 * 1024 * 1024;
pub const OBJECT_SIZE_SMALL_PAGE: u64 = 4 * 1024;
pub const OBJECT_SIZE_VSPACE: u64 = 4 * 1024;
// pub const OBJECT_SIZE_ASID_POOL: u64 = 1 << 12;

pub enum Rights {
    None = 0x0,
    Write = 0x1,
    Read = 0x2,
    Grant = 0x4,
    GrantReply = 0x8,
    All = 0xf,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ArmIrqTrigger {
    Level = 0,
    Edge = 1,
}

enum InvocationLabel {
    // Untyped
    UntypedRetype = 1,
    // TCB
    TcbReadRegisters = 2,
    TcbWriteRegisters = 3,
    TcbCopyRegisters = 4,
    TcbConfigure = 5,
    TcbSetPriority = 6,
    TcbSetMCPriority = 7,
    TcbSetSchedParams = 8,
    TcbSetTimeoutEndpoint = 9,
    TcbSetIPcbuffer = 10,
    TcbSetSpace = 11,
    TcbSuspend = 12,
    TcbResume = 13,
    TcbBindNotification = 14,
    TcbUnbindNotification = 15,
    TcbSetTLSBase = 16,
    // CNode
    CNodeRevoke = 17,
    CNodeDelete = 18,
    CNodeCancelBadgedSends = 19,
    CNodeCopy = 20,
    CNodeMint = 21,
    CNodeMove = 22,
    CNodeMutate = 23,
    CNodeRotate = 24,
    // IRQ
    IrqIssueIrqHandler = 25,
    IrqAckIrq = 26,
    IrqSetIrqHandler = 27,
    IrqClearIrqHandler = 28,
    // Domain
    DomainSetSet = 29,
    // Sched
    SchedControlConfigureFlags = 30,
    SchedContextBind = 31,
    SchedContextUnbind = 32,
    SchedContextUnbindObject = 33,
    SchedContextConsume = 34,
    SchedContextYieldTo = 35,
    // ARM V Space
    ArmVspaceCleanData = 36,
    ArmVspaceInvalidateData = 37,
    ArmVspaceCleanInvalidateData = 38,
    ArmVspaceUnifyInstruction = 39,
    // ARM SMC
    ArmSmcCall = 40,
    // ARM Page table
    ArmPageTableMap = 41,
    ArmPageTableUnmap = 42,
    // ARM Page
    ArmPageMap = 43,
    ArmPageUnmap = 44,
    ArmPageCleanData = 45,
    ArmPageInvalidateData = 46,
    ArmPageCleanInvalidateData = 47,
    ArmPageUnifyInstruction = 48,
    ArmPageGetAddress = 49,
    // ARM Asid
    ArmAsidControlMakePool = 50,
    ArmAsidPoolAssign = 51,
    // ARM IRQ
    ArmIrqIssueIrqHandlerTrigger = 52,
}

pub struct Aarch64Regs {
    pc: u64,
}

impl Invocation {
    pub fn generic(self) {
        // IMPLEMENT
        let (_, _, _): (InvocationLabel, &[u64], &[u64]) = match self {
            Invocation::UntypedRetype { untyped, object_type, size_bits, root, node_index, node_depth, node_offset, num_objects } =>
                                          (InvocationLabel::UntypedRetype, &[untyped, object_type as u64, size_bits, root, node_index, node_depth, node_offset, num_objects], &[root]),
            Invocation::CnodeMint { cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights, badge } =>
                                          (InvocationLabel::UntypedRetype, &[cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights as u64, badge], &[src_root]),
            _ => panic!("fuck")
        };
    }

    // TODO: count should probably be usize...
    pub fn repeat(&mut self, _count: u64, _repeat: Invocation) {
        // IMPLEMENT
    }
}

#[allow(dead_code)]
pub enum Invocation {
    UntypedRetype {
        untyped: u64,
        object_type: ObjectType,
        size_bits: u64,
        root: u64,
        node_index: u64,
        node_depth: u64,
        node_offset: u64,
        num_objects: u64
    },
    TcbSetSchedParams {
        tcb: u64,
        authority: u64,
        mcp: u64,
        priority: u64,
        sched_context: u64,
        fault_ep: u64,
    },
    TcbSetSpace {
        tcb: u64,
        fault_ep: u64,
        cspace_root: u64,
        cspace_root_data: u64,
        vspace_root: u64,
        vspace_root_data: u64,
    },
    TcbSetIpcBuffer {
        tcb: u64,
        buffer: u64,
        buffer_frame: u64,
    },
    TcbWriteRegisters {
        tcb: u64,
        resume: bool,
        arch_flags: u64,
        regs: Aarch64Regs,
    },
    TcbBindNotification {
        tcb: u64,
        notification: u64,
    },
    AsidPoolAssign {
        asid_pool: u64,
        vspace: u64,
    },
    IrqControlGetTrigger {
        irq_control: u64,
        irq: u64,
        trigger: ArmIrqTrigger,
        dest_root: u64,
        dest_index: u64,
        dest_depth: u64,
    },
    IrqHandlerSetNotification {
        irq_handler: u64,
        notification: u64,
    },
    PageTableMap {
        page_table: u64,
        vspace: u64,
        vaddr: u64,
        attr: u64,
    },
    PageMap {
        page: u64,
        vspace: u64,
        vaddr: u64,
        rights: u64,
        attr: u64,
    },
    CnodeMint {
        cnode: u64,
        dest_index: u64,
        dest_depth: u64,
        src_root: u64,
        src_obj: u64,
        src_depth: u64,
        rights: u64,
        badge: u64,
    },
    CnodeCopy {
        cnode: u64,
        dest_index: u64,
        dest_depth: u64,
        src_root: u64,
        src_obj: u64,
        src_depth: u64,
        rights: Rights,
    },
    CnodeMutate {
        cnode: u64,
        dest_index: u64,
        dest_depth: u64,
        src_root: u64,
        src_obj: u64,
        src_depth: u64,
        badge: u64,
    },
    SchedContextConfigureFlags {
        sched_control: u64,
        sched_context: u64,
        budget: u64,
        period: u64,
        extra_refills: u64,
        badge: u64,
        flags: u64,
    }
}
