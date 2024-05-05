use std::fmt;

#[repr(u64)]
#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
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

#[repr(u32)]
#[derive(Copy, Clone)]
#[allow(dead_code)]
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

#[repr(u32)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
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
    TcbSetIpcBuffer = 10,
    TcbSetSpace = 11,
    TcbSuspend = 12,
    TcbResume = 13,
    TcbBindNotification = 14,
    TcbUnbindNotification = 15,
    TcbSetTLSBase = 16,
    // CNode
    CnodeRevoke = 17,
    CnodeDelete = 18,
    CnodeCancelBadgedSends = 19,
    CnodeCopy = 20,
    CnodeMint = 21,
    CnodeMove = 22,
    CnodeMutate = 23,
    CnodeRotate = 24,
    // IRQ
    IrqIssueIrqHandler = 25,
    IrqAckIrq = 26,
    IrqSetIrqHandler = 27,
    IrqClearIrqHandler = 28,
    // Domain
    DomainSetSet = 29,
    // Scheduling
    SchedControlConfigureFlags = 30,
    SchedContextBind = 31,
    SchedContextUnbind = 32,
    SchedContextUnbindObject = 33,
    SchedContextConsume = 34,
    SchedContextYieldTo = 35,
    // ARM VSpace
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

#[derive(Copy, Clone)]
#[allow(dead_code)]
pub struct Aarch64Regs {
    pub pc: u64,
    pub sp: u64,
    pub spsr: u64,
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x29: u64,
    pub x30: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
}

impl Aarch64Regs {
    // Returns a zero-initialised instance
    pub fn new() -> Aarch64Regs {
        Aarch64Regs {
            pc: 0,
            sp: 0,
            spsr: 0,
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x6: 0,
            x7: 0,
            x8: 0,
            x16: 0,
            x17: 0,
            x18: 0,
            x29: 0,
            x30: 0,
            x9: 0,
            x10: 0,
            x11: 0,
            x12: 0,
            x13: 0,
            x14: 0,
            x15: 0,
            x19: 0,
            x20: 0,
            x21: 0,
            x22: 0,
            x23: 0,
            x24: 0,
            x25: 0,
            x26: 0,
            x27: 0,
            x28: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
        }
    }

    pub fn as_slice(&self) -> [u64; 36] {
        [
            self.pc,
            self.sp,
            self.spsr,
            self.x0,
            self.x1,
            self.x2,
            self.x3,
            self.x4,
            self.x5,
            self.x6,
            self.x7,
            self.x8,
            self.x16,
            self.x17,
            self.x18,
            self.x29,
            self.x30,
            self.x9,
            self.x10,
            self.x11,
            self.x12,
            self.x13,
            self.x14,
            self.x15,
            self.x19,
            self.x20,
            self.x21,
            self.x22,
            self.x23,
            self.x24,
            self.x25,
            self.x26,
            self.x27,
            self.x28,
            self.tpidr_el0,
            self.tpidrro_el0,
        ]
    }

    pub fn count(&self) -> u64 {
        // TODO: hack
        1
    }
}

impl InvocationLabel {
    // TODO: not sure whether this should be a method on InvocationLabel or InvocationArgs
    pub fn from_args(args: &InvocationArgs) -> InvocationLabel {
        match args {
            InvocationArgs::UntypedRetype { .. } => InvocationLabel::UntypedRetype,
            InvocationArgs::TcbSetSchedParams { .. } => InvocationLabel::TcbSetSchedParams,
            InvocationArgs::TcbSetSpace { .. } => InvocationLabel::TcbSetSpace,
            InvocationArgs::TcbSetIpcBuffer { .. } => InvocationLabel::TcbSetIpcBuffer,
            InvocationArgs::TcbResume { .. } => InvocationLabel::TcbResume,
            InvocationArgs::TcbWriteRegisters { .. } => InvocationLabel::TcbWriteRegisters,
            InvocationArgs::TcbBindNotification { .. } => InvocationLabel::TcbBindNotification,
            InvocationArgs::AsidPoolAssign { .. } => InvocationLabel::ArmAsidPoolAssign,
            InvocationArgs::IrqControlGetTrigger { .. } => InvocationLabel::ArmIrqIssueIrqHandlerTrigger,
            InvocationArgs::IrqHandlerSetNotification { .. } => InvocationLabel::IrqSetIrqHandler,
            InvocationArgs::PageTableMap { .. } => InvocationLabel::ArmPageTableMap,
            InvocationArgs::PageMap { .. } => InvocationLabel::ArmPageMap,
            InvocationArgs::CnodeMint { .. } => InvocationLabel::CnodeMint,
            InvocationArgs::SchedControlConfigureFlags { .. } => InvocationLabel::SchedControlConfigureFlags,
        }
    }
}

pub struct Invocation {
    label: InvocationLabel,
    args: InvocationArgs,
    repeat: Option<(u64, InvocationArgs)>,
}

impl fmt::Display for Invocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut arg_strs = Vec::new();
        match self.args {
            InvocationArgs::UntypedRetype { untyped, object_type, size_bits, root, node_index, node_depth, node_offset, num_objects } => {
                arg_strs.push(format!("object_type {}", object_type as u64));
                arg_strs.push(format!("size_bits {} (0x{:x})", size_bits, size_bits));
                arg_strs.push(format!("root (cap) {:x}", root));
            },
            // InvocationArgs::TcbSetSchedParams { tcb, authority, mcp, priority, sched_context, fault_ep } =>
            // InvocationArgs::TcbSetSpace { tcb, fault_ep, cspace_root, cspace_root_data, vspace_root, vspace_root_data } =>
            // InvocationArgs::TcbSetIpcBuffer { tcb, buffer, buffer_frame } =>
            // InvocationArgs::TcbResume { tcb } =>
            // InvocationArgs::TcbWriteRegisters { tcb, resume, arch_flags, regs, count } =>
            // InvocationArgs::TcbBindNotification { tcb, notification } =>
            // InvocationArgs::AsidPoolAssign { asid_pool, vspace } =>
            // InvocationArgs::IrqControlGetTrigger { irq_control, irq, trigger, dest_root, dest_index, dest_depth } =>
            // InvocationArgs::IrqHandlerSetNotification { irq_handler, notification } =>
            // InvocationArgs::PageTableMap { page_table, vspace, vaddr, attr } =>
            // InvocationArgs::PageMap { page, vspace, vaddr, rights, attr } =>
            // InvocationArgs::CnodeMint { cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights, badge } =>
            // InvocationArgs::SchedControlConfigureFlags { sched_control, sched_context, budget, period, extra_refills, badge, flags } =>
            _ => arg_strs.push(format!("TODO for {}", self.label as u64)),
        }
        write!(f, "{:<20} - {:<17} - 0x{:<16x} \n{}", self.object_type(), "TODO", 1, arg_strs.join("\n"))
    }
}

impl Invocation {
    pub fn new(args: InvocationArgs) -> Invocation {
        Invocation {
            label: InvocationLabel::from_args(&args),
            args,
            repeat: None,
        }
    }

    /// Convert our higher-level representation of a seL4 invocation
    /// into raw bytes that will be given to the monitor to interpret
    /// at runtime.
    /// Appends to the given data
    pub fn add_raw_invocation(&self, _data: &mut Vec<u8>) {
        let (service, args, extra_caps): (u64, Vec<u64>, Vec<u64>) = self.args.get_args();

        // TODO: use into() instead?
        let label_num = self.label as u64;
        let mut tag = Invocation::message_info_new(label_num, 0, extra_caps.len() as u64, args.len() as u64);
        let mut extra = vec![];
        if let Some((count, repeat)) = self.repeat {
            // TODO: can we somehow check that the variant of repeat InvocationArgs is the same as the invocation?
            tag |= (count - 1) << 32;
            let (repeat_service, repeat_args, repeat_extra_caps) = repeat.get_args();
            extra.push(repeat_service);
            extra.extend(repeat_args);
            extra.extend(repeat_extra_caps);
        }

        let mut all_args = vec![tag, service];
        all_args.extend(extra_caps);
        all_args.extend(args);
    }

    // TODO: count should probably be usize...
    pub fn repeat(&mut self, count: u64, repeat_args: InvocationArgs) {
        assert!(self.repeat.is_none());
        self.repeat = Some((count, repeat_args));
    }

    pub fn message_info_new(label: u64, caps: u64, extra_caps: u64, length: u64) -> u64 {
        assert!(label < (1 << 50));
        assert!(caps < 8);
        assert!(extra_caps < 8);
        assert!(length < 0x80);

        label << 12 | caps << 9 | extra_caps << 7 | length
    }

    pub fn object_type(&self) -> &'static str {
        match self.label {
            InvocationLabel::UntypedRetype => "Untyped",
            InvocationLabel::TcbSetSchedParams |
            InvocationLabel::TcbSetSpace |
            InvocationLabel::TcbSetIpcBuffer |
            InvocationLabel::TcbResume |
            InvocationLabel::TcbWriteRegisters |
            InvocationLabel::TcbBindNotification => "TCB",
            InvocationLabel::ArmAsidPoolAssign => "ASID Pool",
            InvocationLabel::ArmIrqIssueIrqHandlerTrigger => "IRQ Control",
            InvocationLabel::IrqSetIrqHandler => "IRQ Handler",
            InvocationLabel::ArmPageTableMap => "Page Table",
            InvocationLabel::ArmPageMap => "Page",
            InvocationLabel::CnodeMint => "CNode",
            InvocationLabel::SchedControlConfigureFlags => "SchedControl",
            _ => panic!("Unexpected") // TODO
        }
    }
}

impl InvocationArgs {
    pub fn get_args(self) -> (u64, Vec<u64>, Vec<u64>) {
        match self {
            InvocationArgs::UntypedRetype { untyped, object_type, size_bits, root, node_index, node_depth, node_offset, num_objects } =>
                                        (
                                           untyped,
                                           vec![object_type as u64, size_bits, node_index, node_depth, node_offset, num_objects],
                                           vec![root]
                                        ),
            InvocationArgs::TcbSetSchedParams { tcb, authority, mcp, priority, sched_context, fault_ep } =>
                                        (
                                            tcb,
                                            vec![mcp, priority],
                                            vec![authority, sched_context, fault_ep]
                                        ),
            InvocationArgs::TcbSetSpace { tcb, fault_ep, cspace_root, cspace_root_data, vspace_root, vspace_root_data } =>
                                        (
                                            tcb,
                                            vec![tcb, cspace_root_data, vspace_root_data],
                                            vec![fault_ep, cspace_root, vspace_root]
                                        ),
            InvocationArgs::TcbSetIpcBuffer { tcb, buffer, buffer_frame } => (tcb, vec![buffer], vec![buffer_frame]),
            InvocationArgs::TcbResume { tcb } => (tcb, vec![], vec![]),
            InvocationArgs::TcbWriteRegisters { tcb, resume, arch_flags, regs, count } => {
                // TODO: this is kinda fucked
                let resume_byte = if resume { 1 } else { 0 };
                let flags: u64 = ((arch_flags as u64) << 8) | resume_byte;
                let mut args = vec![flags, count];
                args.extend(regs.as_slice());
                (tcb, args, vec![])
            }
            InvocationArgs::TcbBindNotification { tcb, notification } => (tcb, vec![], vec![notification]),
            InvocationArgs::AsidPoolAssign { asid_pool, vspace } => (asid_pool, vec![], vec![vspace]),
            InvocationArgs::IrqControlGetTrigger { irq_control, irq, trigger, dest_root, dest_index, dest_depth } =>
                                        (
                                            irq_control,
                                            vec![irq, trigger as u64, dest_index, dest_depth],
                                            vec![dest_root],
                                        ),
            InvocationArgs::IrqHandlerSetNotification { irq_handler, notification } => (irq_handler, vec![], vec![notification]),
            InvocationArgs::PageTableMap { page_table, vspace, vaddr, attr } =>
                                        (
                                            page_table,
                                            vec![vaddr, attr],
                                            vec![vspace]
                                        ),
            InvocationArgs::PageMap { page, vspace, vaddr, rights, attr } => (page, vec![vaddr, rights as u64, attr], vec![vspace]),
            InvocationArgs::CnodeMint { cnode, dest_index, dest_depth, src_root, src_obj, src_depth, rights, badge } =>
                                        (
                                            cnode,
                                            vec![dest_index, dest_depth, src_root, src_obj, src_depth, rights as u64, badge],
                                            vec![src_root]
                                        ),
            InvocationArgs::SchedControlConfigureFlags { sched_control, sched_context, budget, period, extra_refills, badge, flags } =>
                                        (
                                            sched_control,
                                            vec![budget, period, extra_refills, badge, flags],
                                            vec![sched_context]
                                        )
        }
    }
}

#[derive(Clone, Copy)]
#[allow(dead_code)]
pub enum InvocationArgs {
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
    TcbResume {
        tcb: u64,
    },
    TcbWriteRegisters {
        tcb: u64,
        resume: bool,
        arch_flags: u8,
        count: u64,
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
    SchedControlConfigureFlags {
        sched_control: u64,
        sched_context: u64,
        budget: u64,
        period: u64,
        extra_refills: u64,
        badge: u64,
        flags: u64,
    }
}
