use quick_xml::de::Deserializer;
use serde::{Deserialize};

#[derive(Deserialize, Debug, PartialEq)]
struct ProgramImage {
    #[serde(rename = "@path")]
    path: String,
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct ProtectionDomain {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@priority")]
    priority: String,
    program_image: ProgramImage
}

#[derive(Deserialize, Debug, PartialEq)]
pub struct System {
    pub protection_domain: Vec<ProtectionDomain>,
}

pub fn parse(xml: &str) -> System {
    println!("{}", xml);
    let mut deserializer = Deserializer::from_str(xml);
    let system = System::deserialize(&mut deserializer).unwrap();

    return system;
}
