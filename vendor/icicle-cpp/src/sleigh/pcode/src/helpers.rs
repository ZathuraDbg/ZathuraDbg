#[inline]
pub fn mask(bits: u64) -> u64 {
    u64::MAX >> (u64::BITS - bits as u32)
}

/// Sign-extend a value with `num_bits` to a 64-bit value
#[inline]
pub fn sxt64(value: impl TryInto<u64>, num_bits: u64) -> u64 {
    let value = value.try_into().map_err(|_| "u64 conversion failed").unwrap();
    (((value << (64 - num_bits)) as i64) >> (64 - num_bits)) as u64
}

/// Sign-extend a value with `num_bits` to a 128-bit value
#[inline]
pub fn sxt128(value: impl TryInto<u128>, num_bits: u64) -> u128 {
    let value = value.try_into().map_err(|_| "u128 conversion failed").unwrap();
    (((value << (128 - num_bits)) as i128) >> (128 - num_bits)) as u128
}

/// Formats numeric arguments
#[derive(Clone, Copy, Debug)]
pub struct NumericFormatter {
    pub value: u64,
    pub is_signed: bool,
    pub is_hex: bool,
    pub num_bits: u16,
}

impl core::fmt::Display for NumericFormatter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match (self.is_signed, self.is_hex) {
            (true, true) => {
                let value = sxt64(self.value, self.num_bits as u64) as i64;
                match value < 0 && value != i64::MIN {
                    true => write!(f, "-{:#0x}", -value),
                    false => write!(f, "{:#0x}", value),
                }
            }
            (true, false) => write!(f, "{}", sxt64(self.value, self.num_bits as u64) as i64),
            (false, true) => write!(f, "{:#0x}", self.value),
            (false, false) => write!(f, "{}", self.value),
        }
    }
}

#[inline]
pub fn cast_bool(value: bool) -> u8 {
    match value {
        true => 1,
        false => 0,
    }
}

/// Align `value` to have alignment of at least `alignment` rounded to the next power of 2
pub fn align_up(value: u64, alignment: u64) -> u64 {
    let alignment = alignment.next_power_of_two();
    let mask = alignment.wrapping_sub(1);
    value + ((alignment - (value & mask)) & mask)
}
