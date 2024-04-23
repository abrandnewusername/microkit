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

pub const fn kb(n: usize) -> usize {
    n * 1024
}

pub const fn mb(n: usize) -> usize {
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

