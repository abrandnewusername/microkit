mod sysxml;

use sysxml::parse;
use std::fs;

fn main() {
    let arg_sdf_path = std::env::args().nth(1).expect("no system description path given");
    let xml: String = fs::read_to_string(arg_sdf_path).unwrap();
    let system = parse(&xml);

    for pd in &system.protection_domain {
        println!("PD: {:?}", pd);
    }

    // What is the simplest thing we can do?
    // Run a hello world program, for a particular board.
}
