use std::path::{Path, PathBuf};
use quick_xml::de::Deserializer;
use serde::{Deserialize};
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

#[derive(Deserialize, Debug, PartialEq)]
struct XmlSysIrq {
    #[serde(rename = "@irq")]
    irq: String,
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "@trigger")]
    trigger: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlProgramImage {
    #[serde(rename = "@path")]
    path: String,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlChannelEnd {
    #[serde(rename = "@pd")]
     pub pd: String,
    #[serde(rename = "@id")]
     pub id: String,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlChannel {
    #[serde(rename = "@name")]
    pub ends: Vec<XmlChannelEnd>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlMemoryRegion {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@size")]
    pub size: String,
    #[serde(rename = "@page_size")]
    pub page_size: Option<String>,
    #[serde(rename = "@phys_addr")]
    pub phys_addr: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlProtectionDomain {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@priority")]
    pub priority: String,
    pub program_image: XmlProgramImage,
    #[serde(rename = "irq")]
    pub irqs: Option<Vec<XmlSysIrq>>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlSystemDescription {
    pub protection_domain: Vec<XmlProtectionDomain>,
    pub memory_region: Option<Vec<XmlMemoryRegion>>,
    pub channel: Option<Vec<XmlChannel>>,
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

impl ProtectionDomain {
    fn from_xml(xml: XmlProtectionDomain) -> ProtectionDomain {
        let budget = 1000;
        let period = budget;
        let pp = false;
        let passive = false;
        let program_image = Path::new(&xml.program_image.path).to_path_buf();
        let maps = vec![];
        let irqs;
        if let Some(xml_irqs) = xml.irqs {
            irqs = xml_irqs.into_iter().map(|irq| SysIrq::from_xml(irq)).collect();
        } else {
            irqs = vec![];
        }
        let setvars = vec![];

        // TODO: need to check that parse works as expected. I don't know
        // what format it expects (hex, decimal, binary etc)
        ProtectionDomain {
            name: xml.name,
            priority: xml.priority.parse::<u32>().unwrap(),
            budget,
            period,
            pp,
            passive,
            program_image,
            maps,
            irqs,
            setvars,
        }
    }

    fn from_rxml(xml: &roxmltree::Node) -> ProtectionDomain {
        let budget = 1000;
        let period = budget;
        let pp = false;
        let passive = false;
        let maps = vec![];
        let irqs = vec![];
        let setvars = vec![];

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
                _ => println!("TODO, {:?}", child)
            }
        }

        // TODO: fix this!
        ProtectionDomain {
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
        }
    }
}

impl SysIrq {
    fn from_xml(xml: XmlSysIrq) -> SysIrq {
        // TODO: remove ARM specific trigger and use general thing
        let trigger;
        if let Some(xml_trigger) = xml.trigger {
            trigger = match xml_trigger.as_str() {
                "level" => ArmIrqTrigger::Level,
                "edge" => ArmIrqTrigger::Edge,
                _ => panic!("trigger must be either 'level' or 'edge'")
            }
        } else {
            // Default to level triggered
            trigger = ArmIrqTrigger::Level;
        }

        // TODO: need to actually handle error in case it's not a u64
        let irq = xml.irq.parse::<u64>().unwrap();
        let id = xml.id.parse::<u64>().unwrap();

        SysIrq {
            irq,
            id,
            trigger,
        }
    }
}

impl SysMemoryRegion {
    fn from_xml(xml: XmlMemoryRegion, plat_desc: &PlatformDescription) -> SysMemoryRegion {
        let page_size = if let Some(xml_page_size) = xml.page_size {
            xml_page_size.parse::<u64>().unwrap()
        } else {
            plat_desc.page_sizes[0]
        };

        // TODO: check valid
        let page_size_valid = plat_desc.page_sizes.contains(&page_size);

        let phys_addr = if let Some(xml_phys_addr) = xml.phys_addr {
            Some(xml_phys_addr.parse::<u64>().unwrap())
        } else {
            None
        };

        let page_count = 0; // TODO

        SysMemoryRegion {
            name: xml.name,
            size: xml.size.parse::<u64>().unwrap(),
            page_size: page_size.into(),
            page_count,
            phys_addr,
        }
    }
}

impl Channel {
    fn from_xml(xml: XmlChannel, pds: &Vec<ProtectionDomain>) -> Channel {
        // TODO: what if ends is empty?
        let pd_a = pds.iter().position(|pd| pd.name == xml.ends[0].pd).unwrap();
        let id_a = xml.ends[0].id.parse::<u64>().unwrap();

        let pd_b = pds.iter().position(|pd| pd.name == xml.ends[1].pd).unwrap();
        let id_b = xml.ends[1].id.parse::<u64>().unwrap();

        if id_a > PD_MAX_ID {
            panic!("id must be < {}", PD_MAX_ID + 1);
        }
        if id_b > PD_MAX_ID {
            panic!("id must be < {}", PD_MAX_ID + 1);
        }

        if xml.ends.len() != 2 {
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

impl<'a> SystemDescription {
    fn from_xml(xml: XmlSystemDescription, plat_desc: PlatformDescription) -> SystemDescription {
        let pds: Vec<ProtectionDomain> = xml.protection_domain
                                        .into_iter()
                                        .map(|pd| ProtectionDomain::from_xml(pd))
                                        .collect();
        let mrs = if let Some(xml_memory_regions) = xml.memory_region {
            xml_memory_regions
                .into_iter()
                .map(|mr| SysMemoryRegion::from_xml(mr, &plat_desc))
                .collect()
        } else {
            vec![]
        };
        let channels = if let Some(xml_channels) = xml.channel {
            xml_channels
                .into_iter()
                .map(|ch| Channel::from_xml(ch, &pds))
                .collect()
        } else {
            vec![]
        };
        SystemDescription {
            protection_domains: pds,
            memory_regions: mrs,
            channels,
        }
    }
}

// pub fn parse(xml: &str, plat_desc: PlatformDescription) -> SystemDescription {
//     let mut deserializer = Deserializer::from_str(xml);
//     let system_xml = XmlSystemDescription::deserialize(&mut deserializer).unwrap();

//     SystemDescription::from_xml(system_xml, plat_desc)
// }

pub fn parse(xml: &str, plat_desc: PlatformDescription) -> SystemDescription {
    let doc = roxmltree::Document::parse(xml).unwrap();

    let mut pds = vec![];
    let mut mrs = vec![];
    let mut channels = vec![];

    for root_children in doc.root().children() {
        for child in root_children.children() {
            if !child.is_element() {
                continue;
            }

            println!("{:?}", child);
            match child.tag_name().name() {
                "protection_domain" => pds.push(ProtectionDomain::from_rxml(&child)),
                _ => panic!("TODO")
            }
        }
    }

    SystemDescription {
        protection_domains: pds,
        memory_regions: mrs,
        channels,
    }
}
