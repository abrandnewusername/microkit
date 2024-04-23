use std::path::{Path, PathBuf};
use quick_xml::de::Deserializer;
use serde::{Deserialize};
use crate::sel4::PageSize;

#[derive(Deserialize, Debug, PartialEq)]
struct XmlProgramImage {
    #[serde(rename = "@path")]
    path: String,
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlProtectionDomain {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@priority")]
    pub priority: String,
    pub program_image: XmlProgramImage
}

#[derive(Deserialize, Debug, PartialEq)]
struct XmlSystemDescription {
    pub protection_domain: Vec<XmlProtectionDomain>,
}

#[repr(u8)]
pub enum SysMapPerms {
    Read,
    Write,
    Execute
}

#[derive(Debug, PartialEq, Eq, Hash)]
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

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysIrq {
    irq: u64,
    id: u64,
    // TODO: trigger
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SysSetVar {
    symbol: String,
    region_paddr: Option<String>,
    vaddr: Option<u64>,
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
    fn from_xml(xml: &XmlProtectionDomain) -> ProtectionDomain {
        let budget = 1000;
        let period = budget;
        let pp = false;
        let passive = false;
        let program_image = Path::new(&xml.program_image.path).to_path_buf();
        let maps = vec![];
        let irqs = vec![];
        let setvars = vec![];

        // TODO: need to check that parse works as expected. I don't know
        // what format it expects (hex, decimal, binary etc)
        ProtectionDomain {
            name: xml.name.clone(),
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
}

pub struct SystemDescription {
    pub protection_domains: Vec<ProtectionDomain>,
    pub memory_regions: Vec<SysMemoryRegion>,
}

impl SystemDescription {
    fn from_xml(xml: &XmlSystemDescription) -> SystemDescription {
        let pds = xml.protection_domain.iter().map(|pd| ProtectionDomain::from_xml(&pd)).collect();
        // TODO: sort out mrs
        let mrs = Vec::new();
        SystemDescription {
            protection_domains: pds,
            memory_regions: mrs,
        }
    }
}

pub fn parse(xml: &str) -> SystemDescription {
    println!("{}", xml);
    let mut deserializer = Deserializer::from_str(xml);
    let system_xml = XmlSystemDescription::deserialize(&mut deserializer).unwrap();

    SystemDescription::from_xml(&system_xml)
}
