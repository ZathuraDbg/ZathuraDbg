use crate::{Block, Instruction, Op, Value, VarNode};

pub trait PcodeDisplay<T>: Sized {
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &T) -> std::fmt::Result;
    fn display<'a>(&'a self, ctx: &'a T) -> DisplayWrapper<'a, T, Self> {
        DisplayWrapper { ctx, value: self }
    }
}

pub struct DisplayWrapper<'a, T, U> {
    ctx: &'a T,
    value: &'a U,
}

impl<'a, T, U> std::fmt::Display for DisplayWrapper<'a, T, U>
where
    U: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f, self.ctx)
    }
}

impl<'a, T, U> std::fmt::Debug for DisplayWrapper<'a, T, U>
where
    U: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f, self.ctx)
    }
}

impl<T> PcodeDisplay<T> for Block
where
    Instruction: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &T) -> std::fmt::Result {
        for inst in &self.instructions {
            writeln!(f, "{}", inst.display(ctx))?;
        }
        Ok(())
    }
}

impl<T> PcodeDisplay<T> for Instruction
where
    VarNode: PcodeDisplay<T>,
    UserOpId: PcodeDisplay<T>,
    SpaceId: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &T) -> std::fmt::Result {
        let inputs = self.inputs.get();
        let a = inputs[0].display(ctx);
        let b = inputs[1].display(ctx);
        let out = self.output.display(ctx);

        match self.op {
            Op::Copy => write!(f, "{out} = {a}"),
            Op::Select(var) => {
                write!(f, "{out} = select({})({a}, {b})", VarNode::new(var, 1).display(ctx))
            }
            Op::Subpiece(offset) => write!(f, "{out} = {a}[{offset}]"),
            Op::ZeroExtend => write!(f, "{out} = zext({a})"),
            Op::SignExtend => write!(f, "{out} = sext({a})"),

            Op::IntToFloat => write!(f, "{out} = int2float({a})"),
            Op::UintToFloat => write!(f, "{out} = uint2float({a})"),
            Op::FloatToFloat => write!(f, "{out} = float2float({a})"),
            Op::FloatToInt => write!(f, "{out} = float2int({a})"),

            Op::IntAdd => write!(f, "{out} = {a} + {b}"),
            Op::IntSub => write!(f, "{out} = {a} - {b}"),
            Op::IntXor => write!(f, "{out} = {a} ^ {b}"),
            Op::IntOr => write!(f, "{out} = {a} | {b}"),
            Op::IntAnd => write!(f, "{out} = {a} & {b}"),
            Op::IntMul => write!(f, "{out} = {a} * {b}"),
            Op::IntDiv => write!(f, "{out} = {a} / {b}"),
            Op::IntSignedDiv => write!(f, "{out} = {a} s/ {b}"),
            Op::IntRem => write!(f, "{out} = {a} % {b}"),
            Op::IntSignedRem => write!(f, "{out} = {a} s% {b}"),

            Op::IntLeft => write!(f, "{out} = {a} << {b}"),
            Op::IntRotateLeft => write!(f, "{out} = {a} <<< {b}"),
            Op::IntRight => write!(f, "{out} = {a} >> {b}"),
            Op::IntSignedRight => write!(f, "{out} = {a} s>> {b}"),
            Op::IntRotateRight => write!(f, "{out} = {a} >>> {b}"),

            Op::IntEqual => write!(f, "{out} = {a} == {b}"),
            Op::IntNotEqual => write!(f, "{out} = {a} != {b}"),
            Op::IntLess => write!(f, "{out} = {a} < {b}"),
            Op::IntSignedLess => write!(f, "{out} = {a} s< {b}"),
            Op::IntLessEqual => write!(f, "{out} = {a} <= {b}"),
            Op::IntSignedLessEqual => write!(f, "{out} = {a} s<= {b}"),
            Op::IntCarry => write!(f, "{out} = {a} carry {b}"),
            Op::IntSignedCarry => write!(f, "{out} = {a} scarry {b}"),
            Op::IntSignedBorrow => write!(f, "{out} = {a} sborrow {b}"),

            Op::IntNot => write!(f, "{out} = ~{a}"),
            Op::IntNegate => write!(f, "{out} = -{a}"),
            Op::IntCountOnes => write!(f, "{out} = popcount({a})"),
            Op::IntCountLeadingZeroes => write!(f, "{out} = lzcount({a})"),

            Op::BoolNot => write!(f, "{out} = !{a}"),
            Op::BoolAnd => write!(f, "{out} = {a} && {b}"),
            Op::BoolOr => write!(f, "{out} = {a} || {b}"),
            Op::BoolXor => write!(f, "{out} = {a} ^^ {b}"),

            Op::FloatNegate => write!(f, "{out} = f-{a}"),
            Op::FloatAbs => write!(f, "{out} = abs({a})"),
            Op::FloatSqrt => write!(f, "{out} = sqrt({a})"),
            Op::FloatCeil => write!(f, "{out} = ceil({a})"),
            Op::FloatFloor => write!(f, "{out} = floor({a})"),
            Op::FloatRound => write!(f, "{out} = round({a})"),
            Op::FloatIsNan => write!(f, "{out} = isnan({a})"),

            Op::FloatAdd => write!(f, "{out} = {a} f+ {b}"),
            Op::FloatSub => write!(f, "{out} = {a} f- {b}"),
            Op::FloatMul => write!(f, "{out} = {a} f* {b}"),
            Op::FloatDiv => write!(f, "{out} = {a} f/ {b}"),
            Op::FloatEqual => write!(f, "{out} = {a} f== {b}"),
            Op::FloatNotEqual => write!(f, "{out} = {a} f!= {b}"),
            Op::FloatLess => write!(f, "{out} = {a} f< {b}"),
            Op::FloatLessEqual => write!(f, "{out} = {a} f<= {b}"),

            Op::Load(id) => write!(f, "{out} = {}[{a}]", SpaceId(id).display(ctx)),
            Op::Store(id) => write!(f, "{}[{a}] = {b}", SpaceId(id).display(ctx)),

            Op::Branch(hint) if inputs[0].const_eq(1) => write!(f, "{hint} {b}"),
            Op::Branch(hint) => write!(f, "if {a} {hint} {b}"),

            Op::PcodeBranch(label) if inputs[0].const_eq(1) => write!(f, "jump <{label}>"),
            Op::PcodeBranch(label) => write!(f, "if {a} jump <{label}>"),
            Op::PcodeLabel(label) => write!(f, "<{label}>"),

            Op::Arg(id) => write!(f, "arg{id} = {a}"),
            Op::PcodeOp(id) => {
                let op = UserOpId(id);
                match self.output.is_invalid() {
                    false => write!(f, "{out} = {}({})", op.display(ctx), inputs.display(ctx)),
                    true => write!(f, "{}({})", op.display(ctx), inputs.display(ctx)),
                }
            }
            Op::Hook(id) => {
                let hook = HookIdD(id);
                match self.output.is_invalid() {
                    false => write!(f, "{out} = {}({})", hook.display(&()), inputs.display(ctx)),
                    true => write!(f, "{}({})", hook.display(&()), inputs.display(ctx)),
                }
            }
            Op::HookIf(id) => {
                let hook = HookIdD(id);
                write!(f, "if {} {}()", inputs[0].display(ctx), hook.display(&()))
            }

            Op::TracerLoad(id) => write!(f, "{out} = {}[{a}]", StoreIdD(id).display(&())),
            Op::TracerStore(id) => write!(f, "{}[{a}] = {b}", StoreIdD(id).display(&())),

            Op::Exception => write!(f, "exception({a}, {b})"),

            Op::InstructionMarker => write!(f, "instruction({:#0x})", inputs[0].as_u64()),
            Op::Invalid => write!(f, "invalid"),
        }
    }
}

impl PcodeDisplay<()> for VarNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _: &()) -> std::fmt::Result {
        match self.is_temp() {
            true => VarNode { id: -self.id, ..*self }.fmt(f, &"$U"),
            false => self.fmt(f, &"$r"),
        }
    }
}

impl<'a> PcodeDisplay<&'a str> for VarNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, prefix: &&'a str) -> std::fmt::Result {
        match self.offset {
            0 => write!(f, "{prefix}{}:{}", self.id, self.size),
            offset => write!(f, "{prefix}{}[{}]:{}", self.id, offset, self.size),
        }
    }
}

impl<T> PcodeDisplay<T> for Value
where
    VarNode: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, ctx: &T) -> std::fmt::Result {
        match self {
            Value::Var(v) => write!(f, "{}", v.display(ctx)),
            Value::Const(c, sz) => write!(f, "{:#0x}:{}", c, sz),
        }
    }
}

impl<T> PcodeDisplay<T> for [Value; 2]
where
    Value: PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, ctx: &T) -> std::fmt::Result {
        match self {
            [a, _] if a.is_invalid() => Ok(()),
            [a, b] if b.is_invalid() => write!(f, "{}", a.display(ctx)),
            [a, b] => write!(f, "{}, {}", a.display(ctx), b.display(ctx)),
        }
    }
}

pub struct UserOpId(pub u16);

impl PcodeDisplay<()> for UserOpId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _: &()) -> std::fmt::Result {
        write!(f, "pcode_op<{}>", self.0)
    }
}

pub struct SpaceId(pub u16);

impl PcodeDisplay<()> for SpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _: &()) -> std::fmt::Result {
        match self.0 {
            crate::RAM_SPACE => f.write_str("ram"),
            crate::REGISTER_SPACE => f.write_str("register"),
            crate::RESERVED_SPACE_END.. => write!(f, "mem.{}", self.0),
        }
    }
}

pub struct HookIdD(pub u16);

impl PcodeDisplay<()> for HookIdD {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _: &()) -> std::fmt::Result {
        write!(f, "hook.{}", self.0)
    }
}

pub struct StoreIdD(pub u16);

impl PcodeDisplay<()> for StoreIdD {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, _: &()) -> std::fmt::Result {
        write!(f, "store.{}", self.0)
    }
}
