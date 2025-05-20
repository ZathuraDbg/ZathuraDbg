pub type PatternExprRange = (u32, u32);

pub use sleigh_parse::ast::PatternOp;

/// Encodes an operation that is part of a pattern expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatternExprOp<T> {
    Value(T),
    Constant(u64),
    Not,
    Negate,
    Op(PatternOp),
}

/// Pattern expressions can appear in 3 places, complex constraints, disassembly constant
/// computation, and context modifications.
///
/// Pattern expressions are mostly the same between each of the expression types, how values
/// associated with identifiers are evaluated differently. For example, context modifications need
/// to be evaluated _before_ the instruction has been fully decoded so `inst_next` is not valid, and
/// the offsets for token fields needs to be adjusted.
///
/// To share code we use a common trait to represent the different types of expressions.
pub(crate) trait EvalPatternValue {
    type Value;
    fn eval(&self, value: &Self::Value) -> i64;
}

pub(crate) fn eval_pattern_expr<E>(
    stack: &mut Vec<i64>,
    eval: E,
    expr: &[PatternExprOp<E::Value>],
) -> Option<i64>
where
    E: EvalPatternValue,
{
    // Reserve space for worst case stack usage to avoid reallocation check on the hot path.
    stack.clear();
    stack.reserve(expr.len() / 2 + 1);

    for op in expr {
        let value = match op {
            PatternExprOp::Value(x) => eval.eval(x),
            PatternExprOp::Constant(x) => *x as i64,
            PatternExprOp::Not => !stack.pop()?,
            PatternExprOp::Negate => -stack.pop()?,
            PatternExprOp::Op(op) => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                eval_pattern_op(lhs, op, rhs)
            }
        };

        if stack.capacity() == stack.len() {
            // Hint to the optimizer that we have enough space
            unreachable!();
        }
        stack.push(value);
    }

    stack.pop()
}

pub fn eval_pattern_op(lhs: i64, op: &PatternOp, rhs: i64) -> i64 {
    match op {
        PatternOp::Add => lhs + rhs,
        PatternOp::Sub => lhs - rhs,
        PatternOp::And => lhs & rhs,
        PatternOp::Or => lhs | rhs,
        PatternOp::Xor => lhs ^ rhs,
        PatternOp::IntLeft => lhs.checked_shl(rhs as u32).unwrap_or(0),
        PatternOp::IntRight => {
            let shift = (rhs as u32).min(std::mem::size_of::<i64>() as u32 * 8 - 1);
            lhs >> shift
        }
        PatternOp::Mult => lhs.wrapping_mul(rhs),
        PatternOp::Div => lhs / rhs,
    }
}
