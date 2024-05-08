use std::path::{Path, PathBuf};
use crate::util::{str_to_bool};
use crate::sel4::{PageSize, ArmIrqTrigger, KernelConfig, KernelArch};

///
/// This module is responsible for parsing the System Description Format (SDF)
/// which is based on XML.
/// We do not use any fancy XML, and instead keep things as minimal and simple
/// as possible.
///
/// As much as possible of the validation of the SDF is done when parsing the XML
/// here.
///
/// You will notice that for each type of element (e.g a Protection Domain) has two
/// structs, one that gets passed to the rest of the tool (e.g ProtectionDomain), and
/// one that gets deserialised into (e.g XmlProtectionDomain).
///
/// There are various XML parsing/deserialising libraries within the Rust eco-system
/// but few seem to be concerned with giving any introspection regarding the parsed
/// XML. The roxmltree project allows us to work on a lower-level than something based
/// on serde and so we can report propper user errors.
///

/// Events that come through entry points (e.g notified or protected) are given an
/// identifier that is used as the badge at runtime.
/// On 64-bit platforms, this badge has a limit of 64-bits which means that we are
/// limited in how many IDs a Microkit protection domain has since each ID represents
/// a unique bit.
/// Currently the first bit is used to determine whether or not the event is a PPC
/// or notification. This means we are left with 63 bits for the ID.
/// IDs start at zero.
const PD_MAX_ID: u64 = 62;

const PD_MAX_PRIORITY: u32 = 254;

/// There are some platform-specific properties that must be known when parsing the
/// SDF for error-checking and validation, these go in this struct.
pub struct PlatformDescription {
    /// Note that page sizes should be ordered by size
    page_sizes: Vec<u64>,
}

impl PlatformDescription {
    pub fn new(kernel_config: &KernelConfig) -> PlatformDescription {
        let page_sizes = match kernel_config.arch {
            KernelArch::Aarch64 => vec![0x1000, 0x200_000],
        };

        // TODO
        // assert!(page_sizes.is_sorted());

        PlatformDescription {
            page_sizes,
        }
    }
}

#[repr(u8)]
pub enum SysMapPerms {
    Read = 1,
    Write = 2,
    Execute = 4,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SysMap {
    pub mr: String,
    pub vaddr: u64,
    pub perms: u8,
    pub cached: bool,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SysMemoryRegion {
    pub name: String,
    pub size: u64,
    pub page_size: PageSize,
    pub page_count: u64,
    pub phys_addr: Option<u64>,
}

impl SysMemoryRegion {
    pub fn page_bytes(&self) -> u64 {
        self.page_size as u64
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysIrq {
    pub irq: u64,
    pub id: u64,
    pub trigger: ArmIrqTrigger,
}

// TODO: this is pretty weird since setvar is sometimes
// has region paddr, sometimes vaddr, but never both
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysSetVar {
    pub symbol: String,
    pub region_paddr: Option<String>,
    pub vaddr: Option<u64>,
}

#[derive(Debug)]
pub struct Channel {
    pub pd_a: usize,
    pub id_a: u64,
    pub pd_b: usize,
    pub id_b: u64,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct ProtectionDomain {
    pub name: String,
    pub priority: u32,
    pub budget: u32,
    pub period: u32,
    pub pp: bool,
    pub passive: bool,
    pub program_image: PathBuf,
    pub maps: Vec<SysMap>,
    pub irqs: Vec<SysIrq>,
    pub setvars: Vec<SysSetVar>,
}

impl SysMapPerms {
    fn from_str(s: &str) -> Result<u8, &'static str> {
        let mut perms = 0;
        for c in s.chars() {
            match c {
                'r' => perms |= SysMapPerms::Read as u8,
                'w' => perms |= SysMapPerms::Write as u8,
                'x' => perms |= SysMapPerms::Execute as u8,
                _ => return Err("invalid permissions")
            }
        }

        Ok(perms)
    }
}

impl ProtectionDomain {
    fn from_xml(xml: &roxmltree::Node) -> Result<ProtectionDomain, &'static str> {
        check_attributes(xml, &["name", "priority", "pp", "budget", "period", "passive"]);

        // Default to 1000 microseconds as the budget, with the period defaulting
        // to being the same as the budget as well.
        let budget = 1000;
        let period = budget;
        let pp = false;
        let passive = false;

        let mut maps = Vec::new();
        let mut irqs = Vec::new();
        let mut setvars = Vec::new();

        let mut program_image = None;

        // Default to minimum priority
        let priority = if let Some(xml_priority) = xml.attribute("priority") {
            xml_priority.parse::<u32>().unwrap()
        } else {
            0
        };

        if priority > PD_MAX_PRIORITY {
            panic!("priority must be between 0 and {}", PD_MAX_PRIORITY);
        }

        for child in xml.children() {
            if !child.is_element() {
                continue;
            }

            match child.tag_name().name() {
                "program_image" => {
                    let program_image_path = child.attribute("path").unwrap();
                    program_image = Some(Path::new(program_image_path).to_path_buf());
                },
                "map" => {
                    check_attributes(&child, &["mr", "vaddr", "perms", "cached", "setvar_vaddr"]);
                    let mr = checked_lookup(&child, "mr").to_string();
                    let vaddr = checked_lookup(&child, "vaddr").parse::<u64>().unwrap();
                    let perms = if let Some(xml_perms) = child.attribute("perms") {
                        // TODO: use like a into or from here?
                        SysMapPerms::from_str(xml_perms)?
                    } else {
                        // Default to read-write
                        SysMapPerms::Read as u8 | SysMapPerms::Write as u8
                    };

                    // On all architectures, the kernel does not allow write-only mappings
                    if perms == SysMapPerms::Write as u8 {
                        panic!("perms mut not be 'w', write-only mappings are not allowed")
                    }

                    let cached = if let Some(xml_cached) = child.attribute("cached") {
                        str_to_bool(xml_cached)?
                    } else {
                        // Default to cached
                        true
                    };

                    // TODO: store the index into the memory regions instead?
                    maps.push(SysMap {
                        mr,
                        vaddr,
                        perms,
                        cached
                    });

                    if let Some(setvar_vaddr) = child.attribute("setvar_vaddr") {
                        setvars.push(SysSetVar {
                            symbol: setvar_vaddr.to_string(),
                            region_paddr: None,
                            vaddr: Some(vaddr),
                        });
                    }
                }
                "irq" => {
                    check_attributes(&child, &["irq", "id", "trigger"]);
                    let irq = checked_lookup(&child, "irq").parse::<u64>().unwrap();
                    let id = checked_lookup(&child, "id").parse::<u64>().unwrap();
                    if id > PD_MAX_ID {
                        panic!("id mut be < {}", PD_MAX_ID + 1);
                    }

                    let trigger = if let Some(trigger_str) = child.attribute("trigger") {
                        match trigger_str {
                            "level" => ArmIrqTrigger::Level,
                            "edge" => ArmIrqTrigger::Edge,
                            _ => panic!("trigger must be either 'level' or 'edge'")
                        }
                    } else {
                        // Default the level triggered
                        ArmIrqTrigger::Level
                    };

                    let irq = SysIrq {
                        irq,
                        id,
                        trigger
                    };
                    irqs.push(irq);
                },
                "setvar" => {
                    check_attributes(&child, &["symbol", "region_paddr"]);
                    let symbol = checked_lookup(&child, "symbol").to_string();
                    let region_paddr = Some(checked_lookup(&child, "region_paddr").to_string());
                    setvars.push(SysSetVar {
                        symbol,
                        region_paddr,
                        vaddr: None,
                    })
                }
                _ => println!("TODO, {:?}", child)
            }
        }

        // TODO: fix this!
        Ok(ProtectionDomain {
            name: xml.attribute("name").unwrap().to_string(),
            priority,
            budget,
            period,
            pp,
            passive,
            program_image: program_image.unwrap(),
            maps,
            irqs,
            setvars,
        })
    }
}

impl SysMemoryRegion {
    fn from_xml(xml: &roxmltree::Node, plat_desc: &PlatformDescription) -> SysMemoryRegion {
        check_attributes(xml, &["name", "size", "page_size", "phys_addr"]);

        let name = checked_lookup(xml, "name");
        // TODO: don't unwrap
        let size = checked_lookup(xml, "size").parse::<u64>().unwrap();

        let page_size = if let Some(xml_page_size) = xml.attribute("page_size") {
            xml_page_size.parse::<u64>().unwrap()
        } else {
            // Default to the minimum page size
            plat_desc.page_sizes[0]
        };

        // TODO: check valid
        let page_size_valid = plat_desc.page_sizes.contains(&page_size);
        if !page_size_valid {
            panic!("page size 0x{:x} not supported", page_size);
        }

        if size % page_size != 0 {
            panic!("size is not a multiple of the page size");
        }

        let phys_addr = if let Some(xml_phys_addr) = xml.attribute("phys_addr") {
            Some(xml_phys_addr.parse::<u64>().unwrap())
        } else {
            None
        };

        if !phys_addr.is_none() && phys_addr.unwrap() % page_size != 0 {
            panic!("phys_addr is not aligned to the page size");
        }

        let page_count = size / page_size;

        SysMemoryRegion {
            name: name.to_string(),
            size,
            page_size: page_size.into(),
            page_count,
            phys_addr,
        }
    }
}

impl Channel {
    fn from_xml(xml: &roxmltree::Node, pds: &Vec<ProtectionDomain>) -> Channel {
        check_attributes(xml, &[]);

        let mut ends: Vec<(usize, u64)> = Vec::new();
        for child in xml.children() {
            if !child.is_element() {
                continue;
            }

            match child.tag_name().name() {
                "end" => {
                    check_attributes(&child, &["pd", "id"]);
                    let end_pd = checked_lookup(&child, "pd");
                    let end_id = checked_lookup(&child, "id").parse::<u64>().unwrap();

                    // TODO: check that end_pd exists

                    let pd_idx = pds.iter().position(|pd| pd.name == end_pd).unwrap();

                    ends.push((pd_idx, end_id))
                },
                _ => panic!("Invalid XML element '{}': {}", "TODO", "TODO")
            }
        }

        // TODO: what if ends is empty?
        let (pd_a, id_a) = ends[0];
        let (pd_b, id_b) = ends[1];

        if id_a > PD_MAX_ID {
            value_error(xml, format!("id must be < {}", PD_MAX_ID + 1));
        }
        if id_b > PD_MAX_ID {
            value_error(xml, format!("id must be < {}", PD_MAX_ID + 1));
        }

        if ends.len() != 2 {
            panic!("exactly two end elements must be specified")
        }

        Channel {
            pd_a,
            id_a,
            pd_b,
            id_b,
        }
    }
}

pub struct SystemDescription {
    pub protection_domains: Vec<ProtectionDomain>,
    pub memory_regions: Vec<SysMemoryRegion>,
    pub channels: Vec<Channel>,
}

fn check_attributes(node: &roxmltree::Node, attributes: &[&'static str]) {
    for attribute in node.attributes() {
        if !attributes.contains(&attribute.name()) {
            panic!("invalid attribute '{}'", attribute.name());
        }
    }
}

fn checked_lookup<'a>(node: &'a roxmltree::Node, attribute: &'static str) -> &'a str {
    if let Some(value) = node.attribute(attribute) {
        value
    } else {
        panic!("Missing attribute: {}", "TODO");
    }
}

fn value_error(node: &roxmltree::Node, err: String) {
    panic!("Error: {} on element '{}': {}", err, node.tag_name().name(), "todo")
}

pub fn parse(xml: &str, plat_desc: PlatformDescription) -> Result<SystemDescription, &'static str> {
    let doc = roxmltree::Document::parse(xml).unwrap();

    let mut pds = vec![];
    let mut mrs = vec![];
    let mut channels = vec![];

    for root_children in doc.root().children() {
        for child in root_children.children() {
            if !child.is_element() {
                continue;
            }

            match child.tag_name().name() {
                "protection_domain" => pds.push(ProtectionDomain::from_xml(&child)?),
                // TODO: this is wrong as this assumes that all the protection domains have been
                // parsed at this point which is not true.
                "channel" => channels.push(Channel::from_xml(&child, &pds)),
                "memory_region" => mrs.push(SysMemoryRegion::from_xml(&child, &plat_desc)),
                _ => panic!("TODO")
            }
        }
    }

    Ok(SystemDescription {
        protection_domains: pds,
        memory_regions: mrs,
        channels,
    })
}
