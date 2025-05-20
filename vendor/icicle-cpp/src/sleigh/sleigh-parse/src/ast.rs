use crate::parser::StrIndex;
pub use crate::Span;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ConstraintExprId(u32);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PatternExprId(u32);

#[derive(Default)]
pub struct ExprTable {
    pub items: Vec<Item>,
    pub constraints: Vec<ConstraintItem>,
    pub patterns: Vec<PatternItem>,
}

#[derive(Debug, Clone)]
pub struct Sleigh {
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Item {
    DefineEndian(EndianKind),
    DefineAlignment(u64),
    DefineSpace(Space),
    SpaceNameDef(SpaceNameDef),
    DefineBitRange(Vec<BitRange>),
    DefineUserOp(Ident),
    DefineToken(TokenDef),
    DefineContext(Context),
    AttachVariables(AttachVariables),
    AttachNames(AttachNames),
    AttachValues(AttachValues),
    Macro(Macro),
    With(WithDef),
    Constructor(Constructor),
}

impl ParserDisplay for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::DefineEndian(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::DefineAlignment(x) => f.write_fmt(format_args!("{}", x)),
            Self::DefineSpace(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::SpaceNameDef(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::DefineBitRange(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::DefineUserOp(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::DefineToken(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::DefineContext(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::AttachVariables(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::AttachNames(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::AttachValues(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::Macro(x) => x.fmt(f, p),
            Self::With(x) => f.write_fmt(format_args!("{:?}", x)),
            Self::Constructor(x) => x.fmt(f, p),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Ident(pub StrIndex);

impl ParserDisplay for Ident {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        let ident = p.interner.get(self.0);
        f.write_str(ident)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EndianKind {
    Little,
    Big,
}

impl Default for EndianKind {
    fn default() -> Self {
        Self::Little
    }
}

impl std::str::FromStr for EndianKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "little" => Ok(Self::Little),
            "big" => Ok(Self::Big),
            _ => Err(()),
        }
    }
}

/// Represents the sized associated with a operation on a VarNode, this is _larger_ than
/// \[pcode::VarSize\], which is set after splitting large operations into multiple parts.
pub type VarSize = u16;

pub type Range = (VarSize, VarSize);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Space {
    pub name: Ident,
    pub kind: SpaceKind,
    pub size: VarSize,
    pub word_size: Option<VarSize>,
    pub default: bool,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SpaceKind {
    RamSpace,
    RomSpace,
    RegisterSpace,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SpaceNameDef {
    pub space: Ident,
    pub offset: u64,
    pub size: VarSize,
    pub names: Vec<Ident>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BitRange {
    pub name: Ident,
    pub source: Ident,
    pub range: Range,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TokenDef {
    pub name: Ident,
    pub bits: VarSize,
    pub endian: Option<EndianKind>,
    pub fields: Vec<TokenField>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TokenField {
    pub name: Ident,
    pub range: Range,
    pub signed: bool,
    pub hex: bool,
    pub dec: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Context {
    pub name: Ident,
    pub fields: Vec<ContextField>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ContextField {
    pub name: Ident,
    pub range: Range,
    pub signed: bool,
    pub hex: bool,
    pub dec: bool,
    pub noflow: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachVariables {
    pub fields: Vec<Ident>,
    pub registers: Vec<Ident>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachNames {
    pub fields: Vec<Ident>,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AttachValues {
    pub fields: Vec<Ident>,
    pub values: Vec<i64>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Macro {
    pub name: Ident,
    pub params: Vec<Ident>,
    pub body: Vec<Statement>,
}

impl ParserDisplay for Macro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        write!(f, "macro {}({}) {{ ", self.name.display(p), DisplayList(&self.params).display(p))?;
        for stmt in &self.body {
            write!(f, "{}; ", stmt.display(p))?;
        }
        write!(f, "}}")
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WithDef {
    pub table: Option<Ident>,
    pub constraint: ConstraintExpr,
    pub disasm_actions: Vec<DisasmAction>,
    pub items: Vec<Item>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Constructor {
    pub table: Option<Ident>,
    pub mnemonic: Option<String>,
    pub display: Vec<DisplaySegment>,
    pub constraint: ConstraintExpr,
    pub disasm_actions: Vec<DisasmAction>,
    pub semantics: Vec<Statement>,
    pub span: Span,
}

impl ParserDisplay for Constructor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        let mnemonic = self.mnemonic.as_deref().unwrap_or(" ");
        write!(f, "{}:{}", self.table.display(p), mnemonic)?;

        for entry in &self.display {
            entry.fmt(f, p)?;
        }
        write!(f, " is {} ", self.constraint.display(p))?;

        if !self.disasm_actions.is_empty() {
            f.write_str("[ ")?;
            for entry in &self.disasm_actions {
                write!(f, "{};", entry.display(p))?;
            }
            f.write_str("] ")?;
        }

        f.write_str("{ ")?;
        for entry in &self.semantics {
            write!(f, "{}; ", entry.display(p))?;
        }
        f.write_str("}")
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DisplaySegment {
    Ident(Ident),
    Literal(String),
}

impl From<Ident> for DisplaySegment {
    fn from(v: Ident) -> Self {
        Self::Ident(v)
    }
}

impl From<String> for DisplaySegment {
    fn from(v: String) -> Self {
        Self::Literal(v)
    }
}

impl<'a> From<&'a str> for DisplaySegment {
    fn from(v: &'a str) -> Self {
        Self::Literal(String::from(v))
    }
}

impl ParserDisplay for DisplaySegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Ident(x) => x.fmt(f, p),
            Self::Literal(x) => f.write_str(x),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConstraintItem {
    Ident(Ident),
    Cmp(Ident, ConstraintCmp, PatternExprId),
    Op(ConstraintExprId, ConstraintOp, ConstraintExprId),
    ExtendLeft(ConstraintExprId),
    ExtendRight(ConstraintExprId),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ConstraintExpr {
    Ident(Ident),
    Cmp(Ident, ConstraintCmp, PatternExpr),
    Op(Box<ConstraintExpr>, ConstraintOp, Box<ConstraintExpr>),
    ExtendLeft(Box<ConstraintExpr>),
    ExtendRight(Box<ConstraintExpr>),
}

impl ParserDisplay for ConstraintExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Ident(ident) => ident.fmt(f, p),
            Self::Cmp(ident, op, operand) => {
                write!(f, "{}{}{}", ident.display(p), op, operand.display(p))
            }
            Self::Op(lhs, op, rhs) => {
                match &**lhs {
                    Self::Ident(_) | Self::Cmp(..) => lhs.fmt(f, p)?,
                    _ => write!(f, "({})", lhs.display(p))?,
                }
                write!(f, " {} ", op)?;
                match &**rhs {
                    Self::Ident(_) | Self::Cmp(..) => rhs.fmt(f, p)?,
                    _ => write!(f, "({})", rhs.display(p))?,
                }
                Ok(())
            }
            Self::ExtendLeft(inner) => write!(f, "... ({})", inner.display(p)),
            Self::ExtendRight(inner) => write!(f, "({}) ...", inner.display(p)),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ConstraintCmp {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl std::fmt::Display for ConstraintCmp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equal => f.write_str("="),
            Self::NotEqual => f.write_str("!="),
            Self::Less => f.write_str("<"),
            Self::LessOrEqual => f.write_str("<="),
            Self::Greater => f.write_str(">"),
            Self::GreaterOrEqual => f.write_str(">="),
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ConstraintOp {
    And,
    Or,
    Concat,
}

impl std::fmt::Display for ConstraintOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::And => f.write_str("&"),
            Self::Or => f.write_str("|"),
            Self::Concat => f.write_str(";"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DisasmAction {
    Assignment { ident: Ident, expr: PatternExpr },
    GlobalSet { start_sym: Ident, context_sym: Ident },
}

impl ParserDisplay for DisasmAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Assignment { ident, expr } => {
                write!(f, "{} = {}", ident.display(p), expr.display(p))
            }
            Self::GlobalSet { start_sym, context_sym } => {
                write!(f, "globalset({}, {})", start_sym.display(p), context_sym.display(p))
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PatternItem {
    Ident(Ident),
    Integer(u64),
    Op(PatternExprId, PatternOp, PatternExprId),
    Not(PatternExprId),
    Negate(PatternExprId),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PatternExpr {
    Ident(Ident),
    Integer(u64),
    Op(Box<PatternExpr>, PatternOp, Box<PatternExpr>),
    Not(Box<PatternExpr>),
    Negate(Box<PatternExpr>),
}

impl ParserDisplay for PatternExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Ident(ident) => ident.fmt(f, p),
            Self::Integer(x) => write!(f, "{:#0x}", x),
            Self::Op(lhs, op, rhs) => {
                match &**lhs {
                    Self::Ident(_) | Self::Not(_) | Self::Negate(_) | Self::Integer(_) => {
                        lhs.fmt(f, p)?
                    }
                    _ => write!(f, "({})", lhs.display(p))?,
                }
                write!(f, " {} ", op)?;
                match &**rhs {
                    Self::Ident(_) | Self::Not(_) | Self::Negate(_) | Self::Integer(_) => {
                        rhs.fmt(f, p)?
                    }
                    _ => write!(f, "({})", rhs.display(p))?,
                }
                Ok(())
            }
            Self::Not(x) => match &**x {
                PatternExpr::Ident(_) | PatternExpr::Integer(_) => write!(f, "~{}", x.display(p)),
                _ => write!(f, "~({})", x.display(p)),
            },
            Self::Negate(x) => match &**x {
                PatternExpr::Ident(_) | PatternExpr::Integer(_) => write!(f, "-{}", x.display(p)),
                _ => write!(f, "-({})", x.display(p)),
            },
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PatternOp {
    Add,
    Sub,
    Mult,
    Div,
    IntLeft,
    IntRight,
    And,
    Or,
    Xor,
}

impl std::fmt::Display for PatternOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sym = match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mult => "*",
            Self::Div => "/",
            Self::IntLeft => "<<",
            Self::IntRight => ">>",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
        };
        f.write_str(sym)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BranchHint {
    Jump,
    Call,
    Return,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Statement {
    Unimplemented,

    Export { value: PcodeExpr },
    Local { name: Ident, size: Option<VarSize> },
    LocalAssignment { name: Ident, size: Option<VarSize>, expr: PcodeExpr },
    Build { name: Ident },

    Copy { from: PcodeExpr, to: PcodeExpr },
    Store { space: Option<Ident>, size: Option<VarSize>, pointer: PcodeExpr, value: PcodeExpr },

    Call(PcodeCall),

    Branch { dst: BranchDst, hint: BranchHint },
    CondBranch { cond: PcodeExpr, dst: BranchDst, hint: BranchHint },
    Label { label: Ident },
}

impl ParserDisplay for Statement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Unimplemented => f.write_str("unimplemented"),
            Self::Export { value } => write!(f, "export {}", value.display(p)),
            Self::Local { name, size: Some(size) } => {
                write!(f, "local {}:{}", name.display(p), size)
            }
            Self::Local { name, size: None } => write!(f, "local {}", name.display(p)),
            Self::LocalAssignment { name, size: Some(size), expr } => {
                write!(f, "local {}:{} = {}", name.display(p), size, expr.display(p))
            }
            Self::LocalAssignment { name, size: None, expr } => {
                write!(f, "local {} = {}", name.display(p), expr.display(p))
            }
            Self::Build { name } => write!(f, "build {}", name.display(p)),
            Self::Copy { from, to } => write!(f, "{} = {}", to.display(p), from.display(p)),
            Self::Store { space, size, pointer, value } => {
                let space =
                    space.as_ref().map_or(String::new(), |name| format!("[{}]", name.display(p)));
                let size = size.map_or(String::new(), |size| format!(":{}", size));
                write!(f, "*:{}({}){} = {}", space, pointer.display(p), size, value.display(p))
            }
            Self::Call(call) => write!(f, "{}", call.display(p)),
            Self::Branch { dst, hint } => write!(f, "{:?} {}", hint, dst.display(p)),
            Self::CondBranch { cond, dst, hint } => {
                write!(f, "if {} {} {:?}", cond.display(p), dst.display(p), hint)
            }
            Self::Label { label } => write!(f, "<{}>", label.display(p)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BranchDst {
    Direct(JumpLabel),
    Indirect(JumpLabel),
    Label(Ident),
}

impl ParserDisplay for BranchDst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Direct(inner) => inner.fmt(f, p),
            Self::Indirect(inner) => write!(f, "[{}]", inner.display(p)),
            Self::Label(inner) => write!(f, "<{}>", inner.display(p)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum JumpLabel {
    Ident(Ident),
    Integer(u64, VarSize),
}

impl ParserDisplay for JumpLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Ident(name) => name.fmt(f, p),
            Self::Integer(dst, size) => write!(f, "{:#0x}:{}", dst, size),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PcodeExpr {
    Ident { value: Ident },
    Integer { value: u64 },
    AddressOf { size: Option<VarSize>, value: Ident },
    Truncate { value: Box<PcodeExpr>, size: VarSize },
    SliceBits { value: Box<PcodeExpr>, range: Range },
    Op { a: Box<PcodeExpr>, op: PcodeOp, b: Box<PcodeExpr> },
    Deref { space: Option<Ident>, size: Option<VarSize>, pointer: Box<PcodeExpr> },
    ConstantPoolRef { params: Vec<PcodeExpr> },
    Call(PcodeCall),
}

impl ParserDisplay for PcodeExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Self::Ident { value } => value.fmt(f, p),
            Self::Integer { value } => write!(f, "{:#0x}", value),
            Self::AddressOf { size, value } => {
                let size = size.map_or(String::new(), |size| format!(":{} ", size));
                write!(f, "&{}{}", size, value.display(p))
            }
            Self::Truncate { value, size } => write!(f, "{}:{}", value.display(p), size),
            Self::SliceBits { value, range } => {
                write!(f, "{}[{},{}]", value.display(p), range.0, range.1)
            }
            Self::Op { a, op, b } => write!(f, "{} {} {}", a.display(p), op, b.display(p)),
            Self::Deref { space, size, pointer } => {
                let space =
                    space.as_ref().map_or(String::new(), |space| format!("[{}]", space.display(p)));
                let size = size.map_or(String::new(), |size| format!(":{}", size));
                write!(f, "*{}{} {}", space, size, pointer.display(p))
            }
            Self::ConstantPoolRef { params } => write!(f, "constpoolref({:?})", params),
            Self::Call(call) => write!(f, "{}", call.display(p)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PcodeCall {
    pub name: Ident,
    pub args: Vec<PcodeExpr>,
}

impl ParserDisplay for PcodeCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        write!(f, "{}({})", self.name.display(p), DisplayList(&self.args).display(p))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PcodeOp {
    IntMult,
    IntDiv,
    IntSignedDiv,
    IntRem,
    IntSignedRem,

    IntAdd,
    IntSub,
    IntLeft,
    IntRight,
    IntSignedRight,

    IntSignedLess,
    IntSignedLessEqual,
    IntLess,
    IntLessEqual,
    IntEqual,
    IntNotEqual,

    FloatDiv,
    FloatMult,
    FloatAdd,
    FloatSub,
    FloatLess,
    FloatLessEqual,
    FloatEqual,
    FloatNotEqual,

    IntAnd,
    IntXor,
    IntOr,

    BoolXor,
    BoolAnd,
    BoolOr,

    IntCarry,
    IntSignedCarry,
    IntSignedBorrow,

    IntGreater,
    IntGreaterEqual,
    IntSignedGreater,
    IntSignedGreaterEqual,
    FloatGreater,
    FloatGreaterEqual,
}

impl std::fmt::Display for PcodeOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntMult => f.write_str("*"),
            Self::IntDiv => f.write_str("/"),
            Self::IntSignedDiv => f.write_str("s/"),
            Self::IntRem => f.write_str("%"),
            Self::IntSignedRem => f.write_str("s%"),
            Self::IntAdd => f.write_str("+"),
            Self::IntSub => f.write_str("-"),
            Self::IntLeft => f.write_str("<<"),
            Self::IntRight => f.write_str(">>"),
            Self::IntSignedRight => f.write_str("s>>"),
            Self::IntSignedLess => f.write_str("s<"),
            Self::IntSignedLessEqual => f.write_str("s<="),
            Self::IntLess => f.write_str("<"),
            Self::IntLessEqual => f.write_str("<="),
            Self::IntEqual => f.write_str("=="),
            Self::IntNotEqual => f.write_str("!="),
            Self::FloatDiv => f.write_str("f/"),
            Self::FloatMult => f.write_str("f*"),
            Self::FloatAdd => f.write_str("f+"),
            Self::FloatSub => f.write_str("f-"),
            Self::FloatLess => f.write_str("f<"),
            Self::FloatLessEqual => f.write_str("f<="),
            Self::FloatEqual => f.write_str("f=="),
            Self::FloatNotEqual => f.write_str("f!="),
            Self::IntAnd => f.write_str("&"),
            Self::IntXor => f.write_str("^"),
            Self::IntOr => f.write_str("|"),
            Self::BoolXor => f.write_str("^^"),
            Self::BoolAnd => f.write_str("&&"),
            Self::BoolOr => f.write_str("||"),
            Self::IntCarry => f.write_str("carry"),
            Self::IntSignedCarry => f.write_str("scarry"),
            Self::IntSignedBorrow => f.write_str("sborrow"),
            Self::IntGreater => f.write_str(">"),
            Self::IntGreaterEqual => f.write_str(">="),
            Self::IntSignedGreater => f.write_str("s>"),
            Self::IntSignedGreaterEqual => f.write_str("s>="),
            Self::FloatGreater => f.write_str("f>"),
            Self::FloatGreaterEqual => f.write_str("f>="),
        }
    }
}

pub trait ParserDisplay: Sized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result;
    fn display<'a, 'b>(&'a self, p: &'b crate::Parser) -> ParserDisplayWrapper<'a, 'b, Self> {
        ParserDisplayWrapper { inner: self, parser: p }
    }
}

pub struct ParserDisplayWrapper<'a, 'b, T: ParserDisplay> {
    inner: &'a T,
    parser: &'b crate::Parser,
}

impl<'a, 'b, T: ParserDisplay> std::fmt::Display for ParserDisplayWrapper<'a, 'b, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f, self.parser)
    }
}

struct DisplayList<'a, T>(&'a [T]);

impl<'a, T> std::fmt::Display for DisplayList<'a, T>
where
    T: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, entry) in self.0.iter().enumerate() {
            if i + 1 < self.0.len() {
                write!(f, "{}, ", entry)?;
            }
            else {
                write!(f, "{}", entry)?;
            }
        }
        Ok(())
    }
}

impl<'a, T> ParserDisplay for DisplayList<'a, T>
where
    T: ParserDisplay,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        for (i, entry) in self.0.iter().enumerate() {
            if i + 1 < self.0.len() {
                write!(f, "{}, ", entry.display(p))?;
            }
            else {
                write!(f, "{}", entry.display(p))?;
            }
        }
        Ok(())
    }
}

impl<T> ParserDisplay for Option<T>
where
    T: ParserDisplay,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, p: &crate::Parser) -> std::fmt::Result {
        match self {
            Some(value) => value.fmt(f, p),
            None => Ok(()),
        }
    }
}
