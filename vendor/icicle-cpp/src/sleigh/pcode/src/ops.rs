use std::fmt::Display;

use crate::PcodeDisplay;

/// An identifier associated with a VarNode. 0 is reserved for invalid (or unused) variables.
pub type VarId = i16;

/// Represents a byte offset within a variable.
pub type VarOffset = u8;

/// Represents the number of bytes of a variable.
pub type VarSize = u8;

/// Label for an internal P-Code branch operation.
pub type PcodeLabel = u16;

/// The ID assigned to a custom P-code operation.
pub type PcodeOpId = u16;

/// The ID assigned to a custom function hook.
pub type HookId = u16;

/// The ID associated with a storage location.
pub type StoreId = u16;

/// The ID associated with a particular memory location.
pub type MemId = u16;

/// The memory ID associated with the RAM space.
pub const RAM_SPACE: MemId = 0;

/// The memory ID associated with the register space.
pub const REGISTER_SPACE: MemId = 1;

/// The memory ID after all reserved spaces.
pub const RESERVED_SPACE_END: MemId = 2;

/// Represents a reference to a slice of a P-code variable.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VarNode {
    pub id: VarId,
    pub offset: VarOffset,
    pub size: VarSize,
}

impl std::fmt::Debug for VarNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.display(&()), f)
    }
}

impl VarNode {
    pub const NONE: VarNode = VarNode::new(0, 0);

    /// Create a new varnode with a given ID and size.
    #[inline]
    pub const fn new(id: VarId, size: VarSize) -> Self {
        Self { id, offset: 0, size }
    }

    /// Checks whether this VarNode is unused or is invalid due to an internal error.
    #[inline]
    pub fn is_invalid(&self) -> bool {
        self.id == 0
    }

    /// Checks whether this VarNode is a temporary.
    #[inline]
    pub fn is_temp(&self) -> bool {
        self.id < 0
    }

    #[inline]
    pub fn slice(self, offset: VarOffset, size: VarSize) -> VarNode {
        // @fixme: return an error here instead of panicking? This should be verified by the
        // sleigh-compiler.
        if offset + size > self.size {
            panic!(
                "VarNode::slice: {} (offset) + {} (size) > {} (self.size)",
                offset, size, self.size
            );
        }
        VarNode { offset: self.offset + offset, size, ..self }
    }

    #[inline]
    pub fn truncate(self, size: VarSize) -> VarNode {
        self.slice(0, size)
    }

    #[inline]
    pub fn copy_from(self, src: impl Into<Value>) -> Instruction {
        (self, Op::Copy, Inputs::from(src.into())).into()
    }

    #[inline]
    pub fn zext_from(self, src: impl Into<Value>) -> Instruction {
        match src.into() {
            Value::Const(x, _) => (self, Op::Copy, Inputs::from(Value::Const(x, self.size))).into(),
            Value::Var(x) => (self, Op::ZeroExtend, Inputs::from(x)).into(),
        }
    }

    #[inline]
    pub fn extract_from_const(self, value: u64) -> u64 {
        let value = value >> self.offset;
        if self.size < 8 { value & crate::mask(self.size as u64 * 8) } else { value }
    }
}

impl Default for VarNode {
    fn default() -> Self {
        Self::NONE
    }
}

/// A value that can be used as an input to a P-code operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Value {
    Var(VarNode),
    Const(u64, u8),
}

impl Value {
    /// Create a new invalid value
    #[inline]
    pub fn invalid() -> Self {
        Value::Var(VarNode::NONE)
    }

    /// Gets the value as a u64. Panics if the value is not a constant.
    #[inline]
    pub fn as_u64(&self) -> u64 {
        match self {
            Self::Const(c, _) => *c,
            _ => panic!("Value is not a constant"),
        }
    }

    /// Returns whether the value is a constant.
    #[inline]
    pub fn is_const(&self) -> bool {
        matches!(self, Self::Const(..))
    }

    #[inline]
    /// Checks whether the value is constant and equal to the given value.
    pub fn const_eq(&self, value: u64) -> bool {
        matches!(self, Self::Const(c, _) if *c == value)
    }

    /// Checks whether the value is a valid variable or constant.
    #[inline]
    pub fn is_invalid(&self) -> bool {
        matches!(self, Value::Var(VarNode { id: 0, .. }))
    }

    #[inline]
    pub fn slice(self, offset: VarOffset, size: VarSize) -> Self {
        match self {
            Self::Var(v) => Value::Var(v.slice(offset, size)),
            Self::Const(x, _) => {
                Value::Const((x >> (offset * 8)) & crate::mask(size as u64 * 8), size)
            }
        }
    }

    #[inline]
    pub fn truncate(self, size: VarSize) -> Self {
        self.slice(0, size)
    }

    #[inline(always)]
    pub fn size(self) -> VarSize {
        match self {
            Self::Var(v) => v.size,
            Self::Const(_, size) => size,
        }
    }

    #[inline]
    pub fn copy_to(self, dst: VarNode) -> Instruction {
        (dst, Op::Copy, Inputs::from(self)).into()
    }
}

impl From<VarNode> for Value {
    #[inline(always)]
    fn from(v: VarNode) -> Self {
        Value::Var(v)
    }
}

macro_rules! impl_value_from {
    ($($t:ty),*) => {
        $(
            impl From<$t> for Value {
                fn from(v: $t) -> Self {
                    Value::Const(v as u64, std::mem::size_of::<$t>() as u8)
                }
            }
        )*
    };
}

impl_value_from!(u8, u16, u32, u64, i8, i16, i32, i64);

/// Represents a sequence of P-code operations.
pub struct Block {
    pub instructions: Vec<Instruction>,
    pub next_tmp: VarId,
}

impl Default for Block {
    fn default() -> Self {
        Self { instructions: Default::default(), next_tmp: -1 }
    }
}

impl Block {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn clear(&mut self) {
        self.instructions.clear();
        self.next_tmp = -1;
    }

    #[inline]
    pub fn push(&mut self, instruction: impl Into<Instruction>) {
        self.instructions.push(instruction.into());
    }

    /// Store `a` in `dst` if `cond` is non-zero, otherwise store `b` in `dst`
    pub fn select(
        &mut self,
        dst: VarNode,
        cond: impl Into<Value>,
        a: impl Into<Value>,
        b: impl Into<Value>,
    ) {
        self.gen_select_v2(dst, cond.into(), a.into(), b.into());
    }

    /// Implements a select-like operation using bit operations.
    ///
    /// ```pcode
    /// is_non_zero = cond != 0
    /// mask = zxt(is_non_zero) * 0xffff_ffff;
    /// dst = (mask & a) | ((!mask) & b)
    /// ```
    #[allow(unused)]
    fn gen_select(&mut self, dst: VarNode, cond: Value, a: Value, b: Value) {
        assert!(a.size() == dst.size && b.size() == dst.size);

        let is_non_zero = self.alloc_tmp(1);
        self.push((is_non_zero, Op::IntNotEqual, (cond, Value::Const(0, cond.size()))));

        let mask = self.alloc_tmp(dst.size);
        self.push((mask, Op::ZeroExtend, is_non_zero));
        self.push((mask, Op::IntMul, (mask, Value::Const(u64::MAX, dst.size))));

        let tmp = self.alloc_tmp(dst.size);
        self.push((tmp, Op::IntAnd, (a, mask)));

        self.push((mask, Op::IntNot, mask));
        self.push((dst, Op::IntAnd, (b, mask)));

        self.push((dst, Op::IntOr, (dst, tmp)));
    }

    #[allow(unused)]
    fn gen_select_v2(&mut self, dst: VarNode, cond: Value, a: Value, b: Value) {
        assert!(a.size() == dst.size && b.size() == dst.size);

        let cond_var = match cond {
            Value::Var(var) if var.offset == 0 && var.size == 1 => var,
            _ => {
                let cond_var = self.alloc_tmp(1);
                self.push((cond_var, Op::IntNotEqual, (cond, Value::Const(0, cond.size()))));
                cond_var
            }
        };
        self.push((dst, Op::Select(cond_var.id), (a, b)));
    }

    pub fn invalid(&mut self, msg: &'static str) {
        self.instructions.push(Instruction {
            op: Op::Invalid,
            inputs: Inputs::new(msg.as_ptr() as u64, msg.len() as u64),
            output: VarNode::NONE,
        });
    }

    #[inline]
    pub fn alloc_tmp(&mut self, size: VarSize) -> VarNode {
        let id = self.next_tmp;
        self.next_tmp -= 1;
        VarNode::new(id, size)
    }

    pub fn recompute_next_tmp(&mut self) {
        self.next_tmp = self.next_tmp();
    }

    pub fn next_tmp(&self) -> i16 {
        self.instructions.iter().map(|x| x.output.id).min().map_or(-1, |x| x - 1)
    }

    /// Returns the address of the first instruction marker in the block (or None if there is no
    /// instruction marker).
    pub fn first_addr(&self) -> Option<u64> {
        self.instructions
            .iter()
            .filter(|x| matches!(x.op, Op::InstructionMarker))
            .map(|x| x.inputs.first().as_u64())
            .next()
    }

    /// Returns the address of the instruction containing the operation at `offset`.
    pub fn address_of(&self, offset: usize) -> Option<u64> {
        self.instructions
            .iter()
            .take(offset)
            .filter(|x| matches!(x.op, Op::InstructionMarker))
            .last()
            .map(|x| x.inputs.first().as_u64())
    }

    /// Returns the pcode offset within the current block of the instruction that starts at `addr`.
    pub fn offset_of(&self, addr: u64) -> Option<usize> {
        self.instructions.iter().position(|inst| {
            matches!(inst.op, Op::InstructionMarker) && inst.inputs.first().as_u64() == addr
        })
    }
}

impl Clone for Block {
    fn clone(&self) -> Self {
        Self { instructions: self.instructions.clone(), next_tmp: self.next_tmp }
    }

    fn clone_from(&mut self, source: &Self) {
        self.instructions.clone_from(&source.instructions);
        self.next_tmp = source.next_tmp;
    }
}

impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.instructions.iter()).finish()
    }
}

pub type ConstValue = (u64, u8);

/// Internal representation of the operands for a P-Code operation. Representing them in this way
/// allows the enum tags for the inputs to be merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum InputsImpl {
    _0(u64, u8, u64, u8), // Const, Const
    _1(u64, u8, VarNode), // Const, Var
    _2(VarNode, u64, u8), // Var, Const
    _3(VarNode, VarNode), // Var, Var
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Inputs(InputsImpl);

impl Inputs {
    #[inline]
    pub fn none() -> Self {
        Self::new(Value::invalid(), Value::invalid())
    }

    #[inline]
    pub fn one(a: impl Into<Value>) -> Self {
        Self::new(a.into(), Value::invalid())
    }

    #[inline]
    pub fn new(a: impl Into<Value>, b: impl Into<Value>) -> Self {
        Self(match (a.into(), b.into()) {
            (Value::Const(a, a_sz), Value::Const(b, b_sz)) => InputsImpl::_0(a, a_sz, b, b_sz),
            (Value::Const(a, a_sz), Value::Var(b)) => InputsImpl::_1(a, a_sz, b),
            (Value::Var(a), Value::Const(b, b_sz)) => InputsImpl::_2(a, b, b_sz),
            (Value::Var(a), Value::Var(b)) => InputsImpl::_3(a, b),
        })
    }

    #[inline]
    pub fn get(&self) -> [Value; 2] {
        match self.0 {
            InputsImpl::_0(a, a_sz, b, b_sz) => [Value::Const(a, a_sz), Value::Const(b, b_sz)],
            InputsImpl::_1(a, a_sz, b) => [Value::Const(a, a_sz), Value::Var(b)],
            InputsImpl::_2(a, b, b_sz) => [Value::Var(a), Value::Const(b, b_sz)],
            InputsImpl::_3(a, b) => [Value::Var(a), Value::Var(b)],
        }
    }

    #[inline]
    pub fn first(&self) -> Value {
        self.get()[0]
    }

    #[inline]
    pub fn second(&self) -> Value {
        self.get()[1]
    }
}

impl From<[Value; 2]> for Inputs {
    #[inline]
    fn from([a, b]: [Value; 2]) -> Self {
        Self::new(a, b)
    }
}

impl<T> From<T> for Inputs
where
    T: Into<Value>,
{
    #[inline]
    fn from(v: T) -> Self {
        Self::new(v, Value::invalid())
    }
}

impl<T, U> From<(T, U)> for Inputs
where
    T: Into<Value>,
    U: Into<Value>,
{
    fn from((a, b): (T, U)) -> Self {
        Self::new(a, b)
    }
}

impl<'a> From<&'a [Value]> for Inputs {
    fn from(v: &'a [Value]) -> Self {
        match v {
            [] => Self::new(Value::invalid(), Value::invalid()),
            [a] => Self::new(*a, Value::invalid()),
            [a, b] => Self::new(*a, *b),
            _ => panic!("Invalid number of inputs"),
        }
    }
}

/// Represents a full P-code instruction.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Instruction {
    pub op: Op,
    pub inputs: Inputs,
    pub output: VarNode,
}

impl std::fmt::Debug for Instruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.display(&()), f)
    }
}

impl<T, U> From<(VarNode, Op, T, U)> for Instruction
where
    T: Into<Value>,
    U: Into<Value>,
{
    #[inline]
    fn from((output, op, a, b): (VarNode, Op, T, U)) -> Self {
        Self { op, inputs: Inputs::new(a, b), output }
    }
}

impl<I> From<(VarNode, Op, I)> for Instruction
where
    I: Into<Inputs>,
{
    #[inline]
    fn from((output, op, inputs): (VarNode, Op, I)) -> Self {
        Self { op, inputs: inputs.into(), output }
    }
}

impl<I> From<(Op, I)> for Instruction
where
    I: Into<Inputs>,
{
    #[inline]
    fn from((op, inputs): (Op, I)) -> Self {
        Self { op, inputs: inputs.into(), output: VarNode::NONE }
    }
}

impl From<Op> for Instruction {
    #[inline]
    fn from(op: Op) -> Self {
        Self { op, inputs: Inputs::new(Value::invalid(), Value::invalid()), output: VarNode::NONE }
    }
}

/// P-code operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Copy,
    Select(VarId),
    Subpiece(VarOffset),
    ZeroExtend,
    SignExtend,

    IntToFloat,
    UintToFloat,
    FloatToFloat,
    FloatToInt,

    IntAdd,
    IntSub,
    IntXor,
    IntOr,
    IntAnd,
    IntMul,
    IntDiv,
    IntSignedDiv,
    IntRem,
    IntSignedRem,

    IntLeft,
    IntRotateLeft,
    IntRight,
    IntSignedRight,
    IntRotateRight,

    IntEqual,
    IntNotEqual,
    IntLess,
    IntSignedLess,
    IntLessEqual,
    IntSignedLessEqual,
    IntCarry,
    IntSignedCarry,
    IntSignedBorrow,

    IntNot,
    IntNegate,
    IntCountOnes,
    IntCountLeadingZeroes,

    BoolAnd,
    BoolOr,
    BoolXor,
    BoolNot,

    FloatAdd,
    FloatSub,
    FloatMul,
    FloatDiv,

    FloatNegate,
    FloatAbs,
    FloatSqrt,
    FloatCeil,
    FloatFloor,
    FloatRound,
    FloatIsNan,

    FloatEqual,
    FloatNotEqual,
    FloatLess,
    FloatLessEqual,

    Load(MemId),
    Store(MemId),

    Branch(BranchHint),
    PcodeBranch(PcodeLabel),
    PcodeLabel(PcodeLabel),

    Arg(u16),
    PcodeOp(PcodeOpId),
    Hook(HookId),
    HookIf(HookId),
    TracerLoad(StoreId),
    TracerStore(StoreId),
    Exception,

    InstructionMarker,
    Invalid,
}

impl Op {
    pub fn has_side_effects(&self) -> bool {
        match self {
            Op::TracerLoad(_)
            | Op::TracerStore(_)
            | Op::Load(_)
            | Op::Store(_)
            | Op::PcodeOp(_)
            | Op::Hook(_)
            | Op::HookIf(_)
            | Op::Arg(_)
            | Op::Branch(_)
            | Op::PcodeBranch(_)
            | Op::PcodeLabel(_)
            | Op::Exception
            | Op::InstructionMarker
            | Op::Invalid => true,
            _ => false,
        }
    }

    pub fn is_float(&self) -> bool {
        match self {
            Op::IntToFloat
            | Op::UintToFloat
            | Op::FloatToFloat
            | Op::FloatToInt
            | Op::FloatAdd
            | Op::FloatSub
            | Op::FloatMul
            | Op::FloatDiv
            | Op::FloatNegate
            | Op::FloatAbs
            | Op::FloatSqrt
            | Op::FloatCeil
            | Op::FloatFloor
            | Op::FloatRound
            | Op::FloatIsNan
            | Op::FloatEqual
            | Op::FloatNotEqual
            | Op::FloatLess
            | Op::FloatLessEqual => true,
            _ => false,
        }
    }

    pub fn native_var_sizes(&self) -> (&'static [u8], (&'static [u8], &'static [u8])) {
        static ALL_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        static NONE_SIZE: &[u8] = &[0];
        static BOOL_SIZE: &[u8] = &[1];
        static INT_SIZES: &[u8] = &[1, 2, 4, 8, 16];
        static FLOAT_SIZES: &[u8] = &[4, 8];

        match self {
            Op::Copy | Op::Subpiece(_) => (ALL_SIZES, (ALL_SIZES, NONE_SIZE)),
            Op::Select(_) => (INT_SIZES, (INT_SIZES, INT_SIZES)),

            Op::ZeroExtend | Op::SignExtend => (INT_SIZES, (INT_SIZES, NONE_SIZE)),

            Op::IntToFloat | Op::UintToFloat => (FLOAT_SIZES, (INT_SIZES, NONE_SIZE)),
            Op::FloatToFloat => (FLOAT_SIZES, (FLOAT_SIZES, NONE_SIZE)),
            Op::FloatToInt => (INT_SIZES, (FLOAT_SIZES, NONE_SIZE)),

            Op::IntAdd
            | Op::IntSub
            | Op::IntXor
            | Op::IntOr
            | Op::IntAnd
            | Op::IntMul
            | Op::IntDiv
            | Op::IntSignedDiv
            | Op::IntRem
            | Op::IntSignedRem
            | Op::IntLeft
            | Op::IntRotateLeft
            | Op::IntRight
            | Op::IntSignedRight
            | Op::IntRotateRight => (INT_SIZES, (INT_SIZES, INT_SIZES)),
            Op::IntEqual
            | Op::IntNotEqual
            | Op::IntLess
            | Op::IntSignedLess
            | Op::IntLessEqual
            | Op::IntSignedLessEqual
            | Op::IntCarry
            | Op::IntSignedCarry
            | Op::IntSignedBorrow => (BOOL_SIZE, (INT_SIZES, INT_SIZES)),
            Op::IntNot | Op::IntNegate | Op::IntCountOnes | Op::IntCountLeadingZeroes => {
                (INT_SIZES, (INT_SIZES, NONE_SIZE))
            }

            Op::BoolAnd | Op::BoolOr | Op::BoolXor => (BOOL_SIZE, (BOOL_SIZE, BOOL_SIZE)),
            Op::BoolNot => (BOOL_SIZE, (BOOL_SIZE, NONE_SIZE)),

            Op::FloatAdd | Op::FloatSub | Op::FloatMul | Op::FloatDiv => {
                (FLOAT_SIZES, (FLOAT_SIZES, FLOAT_SIZES))
            }
            Op::FloatNegate
            | Op::FloatAbs
            | Op::FloatSqrt
            | Op::FloatCeil
            | Op::FloatFloor
            | Op::FloatRound => (FLOAT_SIZES, (FLOAT_SIZES, NONE_SIZE)),
            Op::FloatIsNan => (BOOL_SIZE, (FLOAT_SIZES, NONE_SIZE)),
            Op::FloatEqual | Op::FloatNotEqual | Op::FloatLess | Op::FloatLessEqual => {
                (BOOL_SIZE, (FLOAT_SIZES, FLOAT_SIZES))
            }

            Op::Load(_) => (ALL_SIZES, (INT_SIZES, NONE_SIZE)),
            Op::Store(_) => (NONE_SIZE, (INT_SIZES, ALL_SIZES)),

            Op::Branch(_) | Op::PcodeBranch(_) => (NONE_SIZE, (BOOL_SIZE, INT_SIZES)),
            Op::PcodeLabel(_) => (NONE_SIZE, (NONE_SIZE, NONE_SIZE)),

            Op::Arg(_) => (NONE_SIZE, (INT_SIZES, NONE_SIZE)),
            Op::PcodeOp(_) => (ALL_SIZES, (ALL_SIZES, ALL_SIZES)),
            Op::Hook(_) => (NONE_SIZE, (NONE_SIZE, NONE_SIZE)),
            Op::HookIf(_) => (NONE_SIZE, (BOOL_SIZE, NONE_SIZE)),

            Op::Exception => (NONE_SIZE, (&[8], &[8])),

            Op::InstructionMarker => (NONE_SIZE, (&[8], &[8])),
            Op::Invalid => (NONE_SIZE, (NONE_SIZE, NONE_SIZE)),

            Op::TracerLoad(_) | Op::TracerStore(_) => unreachable!("deprecated"),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum BranchHint {
    Jump,
    Call,
    Return,
}

impl std::fmt::Display for BranchHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jump => f.write_str("JUMP"),
            Self::Call => f.write_str("CALL"),
            Self::Return => f.write_str("RETURN"),
        }
    }
}

#[test]
fn statement_size() {
    // These structures are very performance-critical, so we include tests to make sure that stay
    // the same expected size.
    assert_eq!(std::mem::size_of::<Op>(), 4);

    // (value: u64, size: u8, align: [u8; 3])
    assert_eq!(std::mem::size_of::<Value>(), 16);

    // (value: u64, value: u64, size: u8, size: u8, tag: u8, align: [u8; 3])
    assert_eq!(std::mem::size_of::<Inputs>(), 24);
    assert_eq!(std::mem::size_of::<Instruction>(), 32);
}

#[test]
fn inputs_display() {
    let none = Inputs::none();
    assert_eq!(none.get().display(&()).to_string(), "");

    let one = Inputs::one(0x10_u64);
    assert_eq!(one.get().display(&()).to_string(), "0x10:8");

    let two = Inputs::new(0x10_u64, 0x20_u64);
    assert_eq!(two.get().display(&()).to_string(), "0x10:8, 0x20:8");
}
