
pub enum Object {
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

pub enum Rights {
    All = 0xf
}

enum InvocationLabel {
    // Untyped
    UntypedRetype = 1,
    // TCB
    TCBReadRegisters = 2,
    TCBWriteRegisters = 3,
    TCBCopyRegisters = 4,
    TCBConfigure = 5,
    TCBSetPriority = 6,
    TCBSetMCPriority = 7,
    TCBSetSchedParams = 8,
    TCBSetTimeoutEndpoint = 9,
    TCBSetIPCBuffer = 10,
    TCBSetSpace = 11,
    TCBSuspend = 12,
    TCBResume = 13,
    TCBBindNotification = 14,
    TCBUnbindNotification = 15,
    TCBSetTLSBase = 16,
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
    IRQIssueIRQHandler = 25,
    IRQAckIRQ = 26,
    IRQSetIRQHandler = 27,
    IRQClearIRQHandler = 28,
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
    ARMVSpaceClean_Data = 36,
    ARMVSpaceInvalidate_Data = 37,
    ARMVSpaceCleanInvalidate_Data = 38,
    ARMVSpaceUnify_Instruction = 39,
    // ARM SMC
    ARMSMCCall = 40,
    // ARM Page table
    ARMPageTableMap = 41,
    ARMPageTableUnmap = 42,
    // ARM Page
    ARMPageMap = 43,
    ARMPageUnmap = 44,
    ARMPageClean_Data = 45,
    ARMPageInvalidate_Data = 46,
    ARMPageCleanInvalidate_Data = 47,
    ARMPageUnify_Instruction = 48,
    ARMPageGetAddress = 49,
    // ARM Asid
    ARMASIDControlMakePool = 50,
    ARMASIDPoolAssign = 51,
    // ARM IRQ
    ARMIRQIssueIRQHandlerTrigger = 52,
}

struct Aarch64Regs {
    pc: u64,
}

impl Invocation {
    pub fn generic(&self) {
        let (label, bytes, extra_caps) = match self {
            Invocation::UntypedRetype { untyped, object_type, size_bits, root, node_index, node_depth, node_offset, num_objects } =>
                                          (InvocationLabel::UntypedRetype, [untyped, object_type, size_bits, root, node_index, node_depth, node_offset, num_objects], [root]),
            Invocation::CnodeMint { cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights, badge } =>
                                          (InvocationLabel::UntypedRetype, [cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights, badge], [src_root]),
            _ => panic!("fuck")
        };
    }
}

pub enum Invocation {
    UntypedRetype {
        untyped: u64,
        object_type: u64,
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
    AsidPoolAsign {
        asid_pool: u64,
        vspace: u64,
    },
    IrqControlGetTrigger {
        irq_control: u64,
        irq: u64,
        trigger: u64,
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
        rights: u64,
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
