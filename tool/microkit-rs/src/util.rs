use crate::KernelObject;

pub fn msb(x: u64) -> u64 {
    64 - x.leading_zeros() as u64 - 1
}

pub fn lsb(x: u64) -> u64 {
    x.trailing_zeros() as u64
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_msb() {
        assert_eq!(msb(37), 5);
    }

    #[test]
    fn test_lsb() {
        assert_eq!(lsb(36), 2);
        assert_eq!(lsb(37), 0);
    }
}

pub const fn kb(n: u64) -> u64 {
    n * 1024
}

pub const fn mb(n: u64) -> u64 {
    n * 1024 * 1024
}

pub const fn divmod(x: u64, y: u64) -> (u64, u64) {
    (x / y, x % y)
}

pub const fn round_up(n: u64, x: u64) -> u64 {
    let (_, m) = divmod(n, x);
    if m == 0 { n } else { n + x - m}
}

pub const fn round_down(n: u64, x: u64) -> u64 {
    let (_, m) = divmod(n, x);
    if m == 0 { n } else { n - m }
}

pub fn is_power_of_two(n: u64) -> bool {
    assert!(n > 0);
    n & (n - 1) == 0
}

/// Mask out (set to zero) the lower bits from n
pub fn mask_bits(n: u64, bits: u64) -> u64 {
    assert!(n > 0);
    (n >> bits) << bits
}

pub fn mask(n: u64) -> u64 {
    (1 << n) - 1
}

/// Check that all objects in the list are adjacent
pub fn objects_adjacent(objects: &Vec<KernelObject>) -> bool {
    let mut prev_cap_addr = objects[0].cap_addr;
    for obj in &objects[1..] {
        if obj.cap_addr != prev_cap_addr + 1 {
            return false;
        }
        prev_cap_addr = obj.cap_addr;
    }

    true
}

/// Product a 'human readable' string for the size.
///
/// 'strict' means that it must be simply represented.
///  Specifically, it must be a multiple of standard power-of-two.
///  (e.g. KiB, MiB, GiB, TiB, PiB, EiB)
pub fn human_size_strict(size: u64) -> String {
    for (bits, label) in [
        (60, "EiB"),
        (50, "PiB"),
        (40, "TiB"),
        (30, "GiB"),
        (20, "MiB"),
        (10, "KiB"),
        (0, "bytes"),
    ] {
        let base = 1 << bits;
        if size > base {
            let count;
            if base > 0 {
                let (d_count, extra) = divmod(size, base);
                count = d_count;
                if extra != 0 {
                    panic!("size 0x{:x} is not a multiple of standard power-of-two", size);
                }
            } else {
                count = size;
            }
            // TODO: handle commas for thousands like in Python
            return format!("{} {}", count, label);
        }
    }

    panic!("should never reach here in human_size_strict");
}

