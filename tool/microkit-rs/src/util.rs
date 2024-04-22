pub fn msb(x: u64) -> u64 {
    // TODO
    0
}

pub fn lsb(x: u64) -> u64 {
    // TODO
    0
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
    let (d, m) = divmod(n, x);
    if m == 0 { n } else { n + x - m}
}

pub const fn round_down(n: u64, x: u64) -> u64 {
    let (d, m) = divmod(n, x);
    if m == 0 { n } else { n - m }
}

pub fn is_power_of_two(n: u64) -> bool {
    assert!(n > 0);
    n & (n - 1) == 0
}
