mod cases;

use std::cmp::Ordering;

use sleigh_runtime::matcher::{Constraint, MatchCase, Pattern, SequentialMatcher};

use crate::{
    symbols::{SymbolTable, Table},
    Context,
};

use self::cases::byteswap_value;

pub(crate) fn build_sequential_matcher(
    symbols: &SymbolTable,
    table: &Table,
    ctx: &Context,
) -> Result<SequentialMatcher, String> {
    let (mut cases, token_size) = cases::collect_constraints(table, symbols)?;
    sort_overlaps(symbols, ctx, &mut cases, token_size as u8);
    Ok(SequentialMatcher { cases, token_size })
}

struct IndexLinkedList {
    head: Option<usize>,
    order: Vec<Option<usize>>,
}

impl IndexLinkedList {
    fn with_capacity(capacity: usize) -> Self {
        let order = Vec::with_capacity(capacity);
        Self { head: None, order }
    }
    fn final_order(self) -> impl Iterator<Item = usize> {
        std::iter::successors(self.head, move |i| self.order[*i])
    }

    fn insert_before(&mut self, pred: impl Fn(usize) -> bool) {
        let new_index = self.order.len();
        let mut last = &mut self.head;
        let mut current = *last;
        while let Some(current_index) = current {
            if pred(current_index) {
                break;
            }
            last = &mut self.order[current_index];
            current = *last;
        }
        *last = Some(new_index);
        self.order.push(current);
    }
}

/// Constructors are allowed to have overlapping constraints where the constructor with highest
/// number of constrained bits is matched first. Here we take care of sorting the match cases so
/// that to ensure the most constrained constructors are matched first.
fn sort_overlaps(symbols: &SymbolTable, ctx: &Context, cases: &mut [MatchCase], _token_size: u8) {
    // linked-list with index analogous to cases
    let mut order_list = IndexLinkedList::with_capacity(cases.len());
    // insert sort all the cases in the "linked-list"
    for add in cases.iter() {
        order_list.insert_before(|case_index| {
            let case = &cases[case_index];
            let cmp = compare_match_cases(add, case);
            match cmp.ord {
                Some(Ordering::Greater) if cmp.equal_intersection => return true,
                Some(Ordering::Equal)
                    if ctx.verbose
                        && cmp.equal_intersection
                        && add.constructor != case.constructor =>
                {
                    eprintln!(
                        "[warning] different constructor, same pattern: {} {}",
                        symbols.format_constructor_line(case.constructor),
                        symbols.format_constructor_line(add.constructor),
                    );
                }
                None if ctx.verbose
                    && cmp.equal_intersection
                    && add.constructor != case.constructor
                    && find_conflict_solver(add, case, cases).is_none() =>
                {
                    eprintln!(
                        "[warning] unsolved conflict between: {} {}",
                        symbols.format_constructor_line(case.constructor),
                        symbols.format_constructor_line(add.constructor),
                    );
                }
                _ => {}
            }
            false
        });
    }

    // assigned ranks based on the linked list position
    for (rank, index) in order_list.final_order().enumerate() {
        cases[index].rank = rank;
    }

    // Sort cases according to their ranking.
    cases.sort_unstable_by_key(|x| x.rank);
}

/// The result of comparison of two constraints.
#[derive(Debug, PartialEq, Eq)]
struct MatcherOrdering {
    /// If the intersection have the same value.
    pub equal_intersection: bool,
    /// The kind of intersection
    ///
    /// - [Some(Ordering::Equal)]: both self and other set the same bits.
    /// - [Some(Ordering::Less)]: every bit in self is set in other, but other contains bits not
    ///   set in self.
    /// - [Some(Ordering::Greater)]: every bit in other is set in self, but self contains bits not
    ///   set in other.
    /// - [None]: both self and other contains bits not set by the other
    pub ord: Option<Ordering>,
}

/// Returns a mask and value for fields representing the bits with simple
/// constraints.
fn pattern_mask_value_simple(case: &MatchCase) -> (u128, u128) {
    let mask = (case.token.mask as u128) << u64::BITS | case.context.mask as u128;
    let value = (case.token.bits as u128) << u64::BITS | case.context.bits as u128;
    //NOTE value & mask is important because of the complex constraint
    (mask, value & mask)
}

/// Returns the mask for fields representing the bits with complex constraints.
fn pattern_mask_complex(case: &MatchCase) -> u128 {
    let mask = (case.token.mask as u128) << u64::BITS | case.context.mask as u128;
    let value = (case.token.bits as u128) << u64::BITS | case.context.bits as u128;
    !mask & value
}

/// Calculate the ordering of the simple constraints.
fn simple_ordering(case_a: &MatchCase, case_b: &MatchCase) -> MatcherOrdering {
    // restricted bit, but value is not known
    let (mask_a, value_a) = pattern_mask_value_simple(case_a);
    let (mask_b, value_b) = pattern_mask_value_simple(case_b);
    let ord = ordering_from_mask(mask_a, mask_b);
    let same_intersection = match ord {
        Some(Ordering::Equal) => value_a == value_b,
        None => value_a & mask_b == value_b & mask_a,
        Some(Ordering::Greater) => value_a & mask_b == value_b,
        Some(Ordering::Less) => value_b & mask_a == value_a,
    };
    MatcherOrdering { equal_intersection: same_intersection, ord }
}

/// Calculate the ordering of the complex constraints.
fn complex_ordering(case_a: &MatchCase, case_b: &MatchCase) -> Option<Ordering> {
    let mask_complex_a = pattern_mask_complex(case_a);
    let mask_complex_b = pattern_mask_complex(case_b);
    ordering_from_mask(mask_complex_a, mask_complex_b)
}

/// Compare the complex constraints, returning true if the intersection have the
/// same constraint.
fn complex_equal_intersection(case_a: &MatchCase, case_b: &MatchCase) -> bool {
    let intersection = pattern_mask_complex(case_a) & pattern_mask_complex(case_b);
    // @todo: check for equivalent constraints between both complex constraints.
    // https://github.com/icicle-emu/icicle-emu/pull/36#issuecomment-1595633902

    // @todo check if the unmatched constraint are always true on the simple
    // pattern of the other.
    // eg: case_a: simple: 0000____, no complex
    //     case_b: simple: ________, complex: `b0001 == b0203`
    // In this case both patterns conflict. AKA can have the same intersection.
    let constraints_a: usize =
        case_a.constraints.iter().filter(|a| constraint_in_mask(a, intersection)).count();
    let constraints_b: usize =
        case_b.constraints.iter().filter(|b| constraint_in_mask(b, intersection)).count();

    // for now, only identify complex constraints as being identical, if the
    // complex constraint is not affecting the intersection.
    constraints_a == 0 && constraints_b == 0
}

// Returns true if the constraint affect the mask
fn constraint_in_mask(constraint: &Constraint, mask: u128) -> bool {
    let bits = match constraint {
        Constraint::Token { token, field, .. } => {
            let mut bits = field.mask();
            if token.big_endian {
                bits = byteswap_value(bits, token.size as u64 * 8);
            }
            (bits as u128) >> 64
        }
        Constraint::Context { field, .. } => field.mask().into(),
    };
    bits & mask != 0
}

/// Compares the bits set in self with other.
fn compare_match_cases(case_a: &MatchCase, case_b: &MatchCase) -> MatcherOrdering {
    let simple = simple_ordering(case_a, case_b);
    let ord = simple.ord.and_then(|cmp| match (cmp, complex_ordering(case_a, case_b)) {
        (Ordering::Equal, other) => other,
        (Ordering::Less, Some(Ordering::Less | Ordering::Equal))
        | (Ordering::Greater, Some(Ordering::Greater | Ordering::Equal)) => Some(cmp),
        _ => None,
    });
    // avoid calling complex_same_intersection if unnecessary
    let equal_intersection =
        simple.equal_intersection && complex_equal_intersection(case_a, case_b);
    MatcherOrdering { ord, equal_intersection }
}

fn ordering_from_mask(mask_a: u128, mask_b: u128) -> Option<Ordering> {
    let extra_a = mask_a & !mask_b != 0;
    let extra_b = mask_b & !mask_a != 0;
    match (extra_a, extra_b) {
        (false, false) => Some(Ordering::Equal),
        (true, true) => None,
        (true, false) => Some(Ordering::Greater),
        (false, true) => Some(Ordering::Less),
    }
}

// Find the MatchCase that solve the conflict between this conflict.
fn find_conflict_solver(
    conflict_a: &MatchCase,
    conflict_b: &MatchCase,
    cases: &[MatchCase],
) -> Option<usize> {
    let (mask_value_a, value_a) = pattern_mask_value_simple(conflict_a);
    let (mask_value_b, value_b) = pattern_mask_value_simple(conflict_b);
    let mask_solver = mask_value_a | mask_value_b;
    let value_solver = value_a | value_b;

    //@todo check if the complex constraint is equal to the intersection
    cases
        .iter()
        .map(pattern_mask_value_simple)
        .position(|(mask_case, value_case)| mask_case == mask_solver && value_case == value_solver)
}

#[allow(unused)]
fn bit_to_string(case: &Pattern) -> String {
    (0..64)
        .into_iter()
        .map(|bit| match (case.mask >> bit & 1 != 0, case.bits >> bit & 1 != 0) {
            (true, true) => '1',
            (true, false) => '0',
            (false, true) => 'X',
            (false, false) => '_',
        })
        .collect()
}

#[allow(unused)]
fn debug_cases(file: &str, symbols: &SymbolTable, table: &Table, cases: &[MatchCase]) {
    use std::io::Write;

    let mut out = std::fs::File::options().append(true).create(true).open(file).unwrap();

    let table_name = symbols.parser.get_ident_str(table.name);
    let _ = writeln!(out, "{table_name}:");
    let _ = writeln!(out, "| mnemonic | file | context | token |");
    let _ = writeln!(out, "|----|-----|---------|-------|");

    for case in cases {
        let constructor = &symbols.constructors[case.constructor as usize];
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` |",
            constructor.mnemonic.as_ref().map(String::as_str).unwrap_or("∅"),
            symbols.format_constructor_line(case.constructor),
            bit_to_string(&case.context),
            bit_to_string(&case.token),
        );
    }
    let _ = out.write_all(b"\n");
}

#[test]
fn test_compare_bits_set() {
    let default_match = MatchCase {
        constructor: 0,
        rank: 0,
        token: Pattern { bits: 0, mask: 0 },
        context: Pattern { bits: 0, mask: 0 },
        constraints: vec![],
    };
    let a = MatchCase { context: Pattern { bits: 0, mask: 0b01111 }, ..default_match.clone() };
    let b = MatchCase { context: Pattern { bits: 0, mask: 0b11111 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&a, &a).ord, Some(std::cmp::Ordering::Equal));
    assert_eq!(compare_match_cases(&a, &b).ord, Some(std::cmp::Ordering::Less));
    assert_eq!(compare_match_cases(&b, &a).ord, Some(std::cmp::Ordering::Greater),);

    let c = MatchCase { context: Pattern { bits: 0, mask: 0b10000 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&c, &a).ord, None);
    assert_eq!(compare_match_cases(&c, &b).ord, Some(std::cmp::Ordering::Less));

    let ands = MatchCase {
        context: Pattern { bits: 0, mask: 0b11111111100000000000000000000000 },
        ..default_match.clone()
    };
    let tst = MatchCase {
        context: Pattern { bits: 0, mask: 0b11111111100000000000000000011111 },
        ..default_match.clone()
    };
    assert_eq!(compare_match_cases(&ands, &tst).ord, Some(std::cmp::Ordering::Less),);
    assert_eq!(compare_match_cases(&tst, &ands).ord, Some(std::cmp::Ordering::Greater),);

    let asr =
        MatchCase { context: Pattern { bits: 0, mask: 0x8030_ffef }, ..default_match.clone() };
    let orr =
        MatchCase { context: Pattern { bits: 0, mask: 0x8000_ffe0 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&asr, &orr).ord, Some(std::cmp::Ordering::Greater),);
}

#[test]
fn compare_pattern() {
    use cases::BitMatcher;

    let ands = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("_______________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    let tst = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("11111__________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    assert_eq!(compare_match_cases(&tst, &ands).ord, Some(std::cmp::Ordering::Greater));

    // Tokens constrains should _NOT_ be checked before context constraints.
    //
    // (previously we assumed that this was the case because of ordering cycles in the x86
    // specification. However, these were addressed by only considering overlaps for the shared part
    // of each token -- see test below.)
    let a = MatchCase {
        context: BitMatcher::from_str("___").pattern(),
        token: BitMatcher::from_str("_110").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    let b = MatchCase {
        context: BitMatcher::from_str("__1").pattern(),
        token: BitMatcher::from_str("__10").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    assert_eq!(compare_match_cases(&a, &b).ord, None);
}
