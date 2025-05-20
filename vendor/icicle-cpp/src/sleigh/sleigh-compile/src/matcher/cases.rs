use sleigh_parse::ast::{self, ParserDisplay};
use sleigh_runtime::{
    matcher::{Constraint, ConstraintOperand, MatchCase},
    ConstructorId,
};

use crate::symbols::{SymbolTable, Table};

/// Iterates over all the constructors in `table` to build a list of cases that can be used for
/// identifying whether a constructor matches the current decoder state.
///
/// Returns the list of match cases and the number of token bits required for the largest case.
///
/// Note: some of the cases may overlap.
pub(crate) fn collect_constraints(
    table: &Table,
    symbols: &SymbolTable,
) -> Result<(Vec<MatchCase>, usize), String> {
    let mut max_token_bytes = 0;
    let mut cases = vec![];
    for &id in &table.constructors {
        let constructor = &symbols.constructors[id as usize];

        let mut has_valid_constraint = false;
        let mut constraint_err = None;
        for entry in &constructor.constraints {
            let (case, required_bytes) = match build_case_matcher(id, entry) {
                Ok(entry) => entry,
                Err(err) => {
                    // Skip this constraint if it is impossible to satisfy. This sometimes occurs
                    // when multiple constraint expressions are generated due to the use of `|`
                    // expressions in the original specification. For example, this occurs due to
                    // $(THCC) in `ARMTHUMBInstructions.sinc`.
                    //
                    // Note we keep track of the conflict here so we can print an error if is there
                    // is no possible match for the current constructor.
                    constraint_err = Some(err);
                    continue;
                }
            };
            max_token_bytes = max_token_bytes.max(required_bytes);
            cases.push(case);
            has_valid_constraint = true;
        }

        if !has_valid_constraint {
            if let Some(err) = constraint_err {
                // All constraints for this constructor were invalid making it impossible to match.
                return Err(format!(
                    "No valid constraints for {} constructor {}: {}",
                    table.name.display(&symbols.parser),
                    symbols.format_span(&constructor.span),
                    err,
                ));
            }
        }
    }

    Ok((cases, max_token_bytes as usize))
}

fn build_case_matcher(
    constructor: ConstructorId,
    constraint_list: &[Constraint],
) -> Result<(MatchCase, u8), String> {
    let mut tokens = BitMatcher::default();
    let mut context = BitMatcher::default();
    let mut complex = vec![];
    for constraint in constraint_list {
        let context_token = sleigh_runtime::Token::new(8, false);
        match constraint {
            Constraint::Context { field, cmp, operand } => match (cmp, operand) {
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Constant(value)) => {
                    context.add_constraint(context_token, *field, Some(value as u64), false)?;
                }
                // Comparing a field with itself (no op)
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Field(rhs_field))
                    if field == &rhs_field => {}
                _ => {
                    context.add_constraint(context_token, *field, None, false)?;
                    complex.push(constraint.clone())
                }
            },
            Constraint::Token { token, field, cmp, operand } => match (cmp, operand) {
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Constant(value)) => {
                    tokens.add_constraint(*token, *field, Some(value as u64), token.big_endian)?;
                }
                // Comparing a field with itself (no op)
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Field(rhs_field))
                    if field == &rhs_field => {}
                _ => {
                    tokens.add_constraint(*token, *field, None, token.big_endian)?;
                    complex.push(constraint.clone())
                }
            },
        }
    }

    let token_bytes = tokens.bits.len() as u8 / 8;
    if token_bytes > 8 {
        return Err(format!("Constraint requires matching {} bytes", token_bytes));
    }

    let case = MatchCase {
        constructor,
        context: context.pattern(),
        token: tokens.pattern(),
        constraints: complex,
        rank: 0,
    };
    Ok((case, token_bytes))
}

/// mask 0 and bit 1 => restricted but value not known
#[derive(Clone, Default)]
pub(crate) struct BitMatcher {
    bits: BitVec,
    mask: BitVec,
}

impl BitMatcher {
    fn add_constraint(
        &mut self,
        token: sleigh_runtime::Token,
        field: sleigh_runtime::Field,
        value: Option<u64>,
        is_be: bool,
    ) -> Result<(), String> {
        if field.offset as u32 >= u64::BITS {
            return Err(format!("Field offset to large: {}", field.offset));
        }

        let token_offset = token.offset as usize * 8;
        let token_bits = (token.size * 8) as usize;
        self.grow(token_offset + token_bits);

        let mut mask = field.mask();
        if is_be {
            mask = byteswap_value(mask, token_bits as u64);
        }
        let new_mask = BitVec::from_u64(mask, token_bits).shift_start(token_offset);

        let Some(value) = value
        else {
            // complex constrained, just add 1 to the value.
            let value_part = new_mask.and(&self.mask.not());
            self.bits = self.bits.or(&value_part);
            return Ok(());
        };
        // When matching constraints, we always read token bits as LE-encoded bytes as this greatly
        // simplifies what happens when we have overlapping token types. This means we need to swap
        // the bytes in the value and mask before we build the final pattern.
        //
        // @fixme: Ghidra is more restrictive when checking overlapping tokens.
        let mut shifted = value << field.offset;
        if is_be {
            shifted = byteswap_value(shifted, token_bits as u64);
        }
        let bits = BitVec::from_u64(shifted, token_bits).shift_start(token_offset);

        // Check whether the new constraint is incompatible with an existing constraint
        let in_both = new_mask.and(&self.mask);
        if bits.and(&in_both) != self.bits.and(&in_both) {
            let mut isolated = BitMatcher::default();
            isolated.add_constraint(token, field, Some(value), is_be).unwrap();
            return Err(format!(
                "merging ({:?}):\n\tcurrent: {:?}\n\t    new: {:?}",
                field, self, isolated
            ));
        }

        self.bits = self.bits.or(&bits);
        self.mask = self.mask.or(&new_mask);

        Ok(())
    }

    fn grow(&mut self, new_len: usize) {
        self.bits.grow(new_len, false);
        self.mask.grow(new_len, false);
    }

    pub(crate) fn pattern(&self) -> sleigh_runtime::matcher::Pattern {
        sleigh_runtime::matcher::Pattern {
            bits: self.bits.value as u64,
            mask: self.mask.value as u64,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_str(value: &str) -> Self {
        let mut bits = BitVec::default();
        let mut mask = BitVec::default();
        for x in value.chars() {
            let (value_bit, mask_bit) = match x {
                '0' => (false, true),
                '1' => (true, true),
                '_' => (false, false),
                _ => panic!("Invalid char: {}", x),
            };
            bits.push_bit(value_bit);
            mask.push_bit(mask_bit);
        }
        Self { bits, mask }
    }
}

pub(crate) fn byteswap_value(value: u64, bits: u64) -> u64 {
    assert!(bits % 8 == 0 && bits <= 64);
    let mut bytes = value.to_le_bytes();
    bytes[0..(bits / 8) as usize].reverse();
    u64::from_le_bytes(bytes)
}

impl std::fmt::Debug for BitMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"")?;
        for (bit, mask) in self.bits.bit_iter().zip(self.mask.bit_iter()) {
            let value = match (mask, bit) {
                (true, true) => "1",
                (true, false) => "0",
                (false, _) => "_",
            };
            f.write_str(value)?;
        }
        f.write_str("\"")?;
        Ok(())
    }
}

#[derive(Default, Clone, PartialOrd, Ord, Hash, PartialEq, Eq)]
pub(crate) struct BitVec {
    pub value: u128,
    len: u8,
}

impl BitVec {
    /// Creates a new bit vector from a u64 value
    pub fn from_u64(value: u64, len: usize) -> Self {
        let mut bit_vec = Self::default();
        for &byte in &value.to_le_bytes() {
            let mut byte = byte;
            for _ in 0..8 {
                if bit_vec.len as usize >= len {
                    break;
                }
                bit_vec.push_bit(byte & 1 == 1);
                byte >>= 1;
            }
        }
        bit_vec.grow(len, false);
        bit_vec
    }

    /// Returns an iterator over each bit in the bit vector.
    fn bit_iter(&self) -> impl Iterator<Item = bool> {
        let value = self.value;
        (0..self.len).map(move |i| (value >> i) & 1 == 1)
    }

    /// Returns the number of bits in this bit vector.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn push_bit(&mut self, bit: bool) {
        if self.len == 128 {
            panic!("insufficient capacity");
        }
        if bit {
            self.value |= 1 << self.len
        }
        self.len += 1;
    }

    /// Shifts the bit vector by inserting `shift` false values at the start of the vector
    pub fn shift_start(self, shift: usize) -> Self {
        std::iter::repeat(false).take(shift).chain(self.bit_iter()).collect()
    }

    /// Grow the bit vector to contain at least `len` bits, initializing new bits with `value`. Does
    /// nothing if `len` is less than the current length (never truncates).
    fn grow(&mut self, len: usize, value: bool) {
        while self.len() < len {
            self.push_bit(value);
        }
    }

    /// Counts the number of `true` bits in the bit vector.
    fn count_ones(&self) -> usize {
        self.value.count_ones() as usize
    }

    #[allow(unused)]
    pub fn select(&self, mask: &Self) -> Self {
        let mut base: BitVec = self
            .bit_iter()
            .zip(mask.bit_iter())
            .filter(|(_, mask)| *mask)
            .map(|(bit, _)| bit)
            .collect();
        base.grow(mask.count_ones(), false);
        base
    }

    /// Performs a bit-wise `not` operation (invert).
    #[allow(unused)]
    fn not(&self) -> Self {
        self.bit_iter().map(|x| !x).collect()
    }

    /// Perform an `and` operation with another BitVec.
    ///
    /// If the inputs are of different length, the result will be resized with `false` to the size
    /// of the largest input.
    fn and(&self, other: &Self) -> Self {
        let len = self.len().max(other.len()) as u8;
        Self { value: self.value & other.value, len }
    }

    /// Performs a bit-wise 'or' operation between two inputs, if the inputs are of different
    /// length, then the result will be the length of the largest input.
    fn or(&self, other: &Self) -> Self {
        let len = self.len().max(other.len()) as u8;
        Self { value: self.value | other.value, len }
    }
}

impl<const N: usize> From<[bool; N]> for BitVec {
    fn from(bits: [bool; N]) -> Self {
        bits.into_iter().collect()
    }
}

impl std::iter::FromIterator<bool> for BitVec {
    fn from_iter<T: IntoIterator<Item = bool>>(iter: T) -> Self {
        let mut value = Self::default();
        iter.into_iter().for_each(|bit| value.push_bit(bit));
        value
    }
}

impl std::fmt::Debug for BitVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"")?;
        for bit in self.bit_iter() {
            f.write_str(if bit { "1" } else { "0" })?;
        }
        f.write_str("\"")?;
        Ok(())
    }
}

#[test]
fn bit_vec() {
    let a = BitVec::from([true, true, true, true]);
    let b = BitVec::from([true, true, true, true, true]);
    assert_eq!(a.select(&b), BitVec::from([true, true, true, true, false]));

    assert_eq!(a.count_ones(), 4);
    assert_eq!(b.count_ones(), 5);

    let a = BitVec::from([true, true, false, true]);
    let b = BitVec::from([false, false, true, true, false]);
    assert_eq!(a.select(&b), BitVec::from([false, true]));

    let a = BitVec::from([true, true, true, true]);
    let b = BitVec::from([true, true, true]);
    assert_eq!(a.and(&b), BitVec::from([true, true, true, false]));
    assert_eq!(a.or(&b), BitVec::from([true, true, true, true]));
}
