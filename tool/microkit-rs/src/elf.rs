use std::fs;
use std::path::Path;

#[repr(C, packed)]
struct ElfHeader32 {
    ident_data: u8,
    ident_version: u8,
    ident_osabi: u8,
    ident_abiversion: u8,
    _padding: [u8; 7],
    type_: u16,
    machine: u16,
    version: u32,
    entry: u32,
    phoff: u32,
    shoff: u32,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}


#[repr(C, packed)]
#[derive(Copy, Clone)]
struct ElfSymbol64 {
    name: u32,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

#[repr(C, packed)]
struct ElfSectionHeader64 {
    name: u32,
    type_: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
}

#[repr(C, packed)]
struct ElfProgramHeader64 {
    type_: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[repr(C, packed)]
struct ElfHeader64 {
    ident_data: u8,
    ident_version: u8,
    ident_osabi: u8,
    ident_abiversion: u8,
    _padding: [u8; 7],
    type_: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";

// TODO: is this worth it?
enum WordSize {
    ThirtyTwo = 32,
    SixtyFour = 64
}

pub struct ElfSegment {
    pub data: Vec<u8>,
    pub phys_addr: u64,
    pub virt_addr: u64,
    loadable: bool,
    attrs: u32,
}

enum SegmentAttributes {
    PF_X = 0x1,
    PF_W = 0x2,
    PF_R = 0x4
}

pub struct ElfFile {
    word_size: WordSize,
    entry: u64,
    pub segments: Vec<ElfSegment>,
    // TODO: figure out how to have this struct be generic for 64-bit and 32-bit?
    symbols: Vec<(String, ElfSymbol64)>,
}

impl ElfFile {
    // TODO: error messages could be better by specifying which ELF we are dealing with
    // TODO: not sure about having String as the result type? Why didn't &str work?
    pub fn from_path(path: &Path) -> Result<ElfFile, String> {
        // TODO: check for errors
        let bytes = fs::read(path).unwrap();

        let magic = &bytes[0..4];
        if magic != ELF_MAGIC {
            return Err("Incorrect magic".to_string());
        }

        let word_size;
        let hdr_size;

        let class = &bytes[4..5][0];
        match class {
            1 => {
                hdr_size = std::mem::size_of::<ElfHeader32>();
                word_size = WordSize::ThirtyTwo;
            },
            2 => {
                hdr_size = std::mem::size_of::<ElfHeader64>();
                word_size = WordSize::SixtyFour;
            },
            _ => return Err(format!("Invalid class '{}'", class)),
        };

        // Now need to read the header into a struct
        let hdr_bytes = &bytes[5..5 + hdr_size];
        // TODO: handle 32-bit
        // TODO: I'm not sure about whether this line is correct regarding alignment etc
        let (head, body, _tail) = unsafe { hdr_bytes.align_to::<ElfHeader64>() };
        assert!(head.is_empty(), "Data was not aligned");
        let hdr = &body[0];
        let entry = hdr.entry;

        // Read all the segments
        let mut segments = Vec::new();
        for i in 0..hdr.phnum {
            let phent_start = hdr.phoff + (i * hdr.phentsize) as u64;
            let phent_end = phent_start + (hdr.phentsize as u64);
            let phent_bytes = &bytes[phent_start as usize..phent_end as usize];
            // TODO: handle 32-bit
            let (phent_head, phent_body, _phent_tail) = unsafe { phent_bytes.align_to::<ElfProgramHeader64>() };
            assert!(phent_head.is_empty(), "phent data was not aligned");
            let phent = &phent_body[0];
            // TODO: sort out conversions
            let data = &bytes[phent.offset as usize..(phent.offset + phent.filesz) as usize];
            // TODO: there is probably a better way of putting the data and zeroes together
            let mut segment_data = Vec::from(data);
            segment_data.extend(vec![0; (phent.memsz - phent.filesz) as usize]);
            let segment = ElfSegment {
                data: segment_data,
                phys_addr: phent.paddr,
                virt_addr: phent.vaddr,
                loadable: phent.type_ == 1,
                attrs: phent.flags
            };

            segments.push(segment)
        }

        // Read all the section headers
        let mut shents = Vec::new();
        let mut symtab_shent: Option<&ElfSectionHeader64> = None;
        let mut shstrtab_shent: Option<&ElfSectionHeader64> = None;
        for i in 0..hdr.shnum {
            let shent_start = hdr.shoff + (i * hdr.shentsize) as u64;
            let shent_end = shent_start + hdr.shentsize as u64;
            let shent_bytes = &bytes[shent_start as usize..shent_end as usize];
            let (shent_head, shent_body, _shent_tail) = unsafe { shent_bytes.align_to::<ElfSectionHeader64>() };
            let shent = &shent_body[0];
            match shent.type_ {
                2 => symtab_shent = Some(shent),
                3 => shstrtab_shent = Some(shent),
                _ => {}
            }
            shents.push(shent);
        }

        if shstrtab_shent.is_none() {
            return Err("Unable to find string table section".to_string());
        }

        assert!(!symtab_shent.is_none());
        if symtab_shent.is_none() {
            return Err("Unable to find symbol table section".to_string());
        }

        // Reading the symbol table
        let symtab_start = symtab_shent.unwrap().offset as usize;
        let symtab_end = symtab_start + symtab_shent.unwrap().size as usize;
        let symtab = &bytes[symtab_start..symtab_end];

        let symtab_str_shent = shents[symtab_shent.unwrap().link as usize];
        let symtab_str_start = symtab_str_shent.offset as usize;
        let symtab_str_end = symtab_str_start + symtab_str_shent.size as usize;
        let symtab_str = &bytes[symtab_str_start..symtab_str_end];

        // Read all the symbols
        let mut symbols = Vec::new();
        let mut offset = 0;
        let symbol_size = std::mem::size_of::<ElfSymbol64>();
        while offset < symtab.len() {
            let sym_bytes = &symtab[offset..offset + symbol_size];
            let (sym_head, sym_body, _sym_tail) = unsafe { sym_bytes.align_to::<ElfSymbol64>() };
            let sym = sym_body[0];
            let name = Self::get_string(symtab_str, sym.name as usize);
            symbols.push((name.to_string(), sym));
            offset += symbol_size;
        }

        Ok(ElfFile { word_size, entry, segments, symbols })
    }

    fn get_string(strtab: &[u8], idx: usize) -> &str {
        // TODO: do not unwrap
        let end_idx = idx + strtab[idx..].iter().position(|&b| b == 0).unwrap();
        std::str::from_utf8(&strtab[idx..end_idx]).unwrap()
    }

    // pub fn phys_mem_regions(alignment: usize) -> Vec<MemoryRegion> {
    //     assert!(alignment > 0);
    // }
}
