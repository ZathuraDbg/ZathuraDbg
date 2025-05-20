use crate::{
    decoder::Decoder,
    expr::{eval_pattern_expr, EvalPatternValue, PatternExprOp},
    ConstructorId, Field, Token,
};

pub type ConstraintOp = sleigh_parse::ast::ConstraintOp;
pub type ConstraintCmp = sleigh_parse::ast::ConstraintCmp;

// @fixme: Currently we only support matching instructions using a linear scan. It should be
// possible to implement this more efficiently (e.g., using a mask & match strategy), however due to
// the way the Sleigh specification is designed sometimes a linear search is necessary (e.g., for
// handling cases where there are multiple matching constructors) so we need this matcher anyway.
//
// For current use cases this linear search is "fast enough".
pub type Matcher = SequentialMatcher;

/// A matcher for finding the correct constructor using a linear scan.
///
/// Note: The matcher checks constructor constraints in the order they are defined, therefore if
/// there are multiple matching constructors the most specific one should be ordered first.
pub struct SequentialMatcher {
    /// The set of constructor constraints that can be matched at the current position.
    pub cases: Vec<MatchCase>,

    /// The size of the largest token checked by the matcher.
    pub token_size: usize,
}

impl SequentialMatcher {
    /// Find the first constructor starting at `offset` that matches the current context. On a
    /// match, the constructor ID and the offset of the _next_ cases is returned.
    pub fn match_constructor(
        &self,
        state: &Decoder,
        offset: usize,
    ) -> Option<(ConstructorId, usize)> {
        let context = state.context;
        let token = state.get_raw_token(0, self.token_size);
        let (position, case) = self
            .cases
            .iter()
            .enumerate()
            .skip(offset)
            .find(|(_, case)| case.matches(state, context, token))?;
        Some((case.constructor, position + 1))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MatchCase {
    /// The constructor id of the matched constructor.
    pub constructor: ConstructorId,

    /// The rank assigned to this constructor, used to control the order the matching algorithm
    /// checks for a match.
    pub rank: usize,

    /// Constraints on the token bits at the current offset.
    pub token: Pattern,

    /// Constraints on the current value of the context register.
    pub context: Pattern,

    /// Additional constraints that cannot be represented as a pattern (uncommon).
    pub constraints: Vec<Constraint>,
}

impl MatchCase {
    fn matches(&self, state: &Decoder, context_reg: u64, token: u64) -> bool {
        self.context.matches(context_reg)
            && self.token.matches(token)
            && (self.constraints.is_empty() || self.matches_complex(state))
    }

    #[cold]
    fn matches_complex(&self, state: &Decoder) -> bool {
        self.constraints.iter().all(|x| x.matches(state))
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct Pattern {
    pub bits: u64,
    pub mask: u64,
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;

        for bit in 0..u64::BITS {
            match ((self.mask >> bit) & 1 != 0, (self.bits >> bit) & 1 != 0) {
                (true, true) => f.write_char('1')?,
                (true, false) => f.write_char('0')?,
                (false, true) => f.write_char('X')?,
                (false, false) => f.write_char('_')?,
            }
        }
        Ok(())
    }
}

impl Pattern {
    pub fn matches(&self, other: u64) -> bool {
        self.mask & self.bits == self.mask & other
    }
}

/// Represents the RHS of a constraint expression.
///
/// Note: Since full expressions are almost never used by real-world SLEIGH specifications we have
/// special cases for constants, and field expressions to improve performance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintOperand {
    Constant(i64),
    Field(Field),
    Expr(Vec<PatternExprOp<Field>>),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Constraint {
    Token { token: Token, field: Field, cmp: ConstraintCmp, operand: ConstraintOperand },
    Context { field: Field, cmp: ConstraintCmp, operand: ConstraintOperand },
}

impl Constraint {
    pub fn matches(&self, state: &Decoder) -> bool {
        match self {
            Self::Token { token, field, cmp, operand } => {
                eval_constraint(*field, state.get_token(*token), operand, *cmp)
            }
            Self::Context { field, cmp, operand } => {
                eval_constraint(*field, state.context, operand, *cmp)
            }
        }
    }
}

struct ConstraintEvalCtx {
    src_val: u64,
}

impl EvalPatternValue for ConstraintEvalCtx {
    type Value = Field;

    fn eval(&self, value: &Self::Value) -> i64 {
        value.extract(self.src_val)
    }
}
fn eval_constraint(
    field: Field,
    src_val: u64,
    operand: &ConstraintOperand,
    cmp: ConstraintCmp,
) -> bool {
    let lhs = field.extract(src_val);
    let rhs = match operand {
        ConstraintOperand::Constant(x) => *x,
        ConstraintOperand::Field(field) => field.extract(src_val),
        ConstraintOperand::Expr(expr) => {
            // @todo: consider reusing allocations here.
            let mut stack = vec![];
            eval_pattern_expr(&mut stack, ConstraintEvalCtx { src_val }, expr).unwrap_or(0)
        }
    };
    match cmp {
        ConstraintCmp::Equal => lhs == rhs,
        ConstraintCmp::NotEqual => lhs != rhs,
        ConstraintCmp::Less => lhs < rhs,
        ConstraintCmp::LessOrEqual => lhs <= rhs,
        ConstraintCmp::Greater => lhs > rhs,
        ConstraintCmp::GreaterOrEqual => lhs >= rhs,
    }
}
