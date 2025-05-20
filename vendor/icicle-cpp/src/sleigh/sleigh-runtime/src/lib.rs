mod debug;
mod decoder;
mod disasm;
mod lifter;

pub mod const_eval;
pub mod expr;
pub mod matcher;
pub mod semantics;

use std::{collections::HashMap, fmt::Display};

pub use crate::{
    decoder::{ContextModValue, Decoder, DisasmConstantValue, Instruction, SubtableCtx},
    expr::PatternExprOp,
    lifter::{Error as LifterError, Lifter},
};
use crate::{
    expr::PatternExprRange,
    matcher::Matcher,
    semantics::{Export, PcodeTmp, SemanticAction, ValueSize},
};

pub const DEBUG: bool = false;

/// The [TableId] associated with the root-level table.
pub const ROOT_TABLE_ID: TableId = 0;

/// The size (in bytes) of the largest supported register for the runtime.
const MAX_REG_SIZE: u8 = 16;

#[derive(Debug, Copy, Clone)]
pub struct RuntimeConfig {
    /// The initial value of the context register used for decoding.
    pub context: u64,
    /// Controls whether the decoder should attempt to decode any delay slots present in the
    /// instruction.
    pub ignore_delay_slots: bool,
    /// Controls whether backtracking is allowed during constructor matching.
    pub allow_backtracking: bool,
    /// Controls whether the runtime context value will be updated as a result of `globalset`
    /// actions during instruction decoding.
    pub update_context: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            context: 0,
            ignore_delay_slots: false,
            allow_backtracking: true,
            update_context: true,
        }
    }
}

pub struct Runtime {
    pub context: u64,
    update_context: bool,
    lifter: Lifter,
    state: Decoder,
    disasm: String,
    instruction: Instruction,
}

impl Runtime {
    pub fn new(context: u64) -> Self {
        Self::new_with_config(&RuntimeConfig { context, ..Default::default() })
    }

    pub fn new_with_config(config: &RuntimeConfig) -> Self {
        let mut decoder = Decoder::new();
        decoder.allow_backtracking = config.allow_backtracking;
        decoder.ignore_delay_slots = config.ignore_delay_slots;

        Self {
            context: config.context,
            lifter: Lifter::new(),
            state: decoder,
            update_context: config.update_context,
            disasm: String::new(),
            instruction: Instruction::default(),
        }
    }

    pub fn decode(
        &mut self,
        sleigh: &'_ SleighData,
        addr: u64,
        bytes: &'_ [u8],
    ) -> Option<&Instruction> {
        self.state.global_context = self.context;
        self.state.set_inst(addr, bytes);
        sleigh.decode_into(&mut self.state, &mut self.instruction)?;
        if self.update_context {
            self.context = self.state.global_context;
        }
        Some(&self.instruction)
    }

    pub fn disasm(&mut self, sleigh: &'_ SleighData) -> Option<&str> {
        self.disasm.clear();
        sleigh.disasm_into(&self.instruction, &mut self.disasm)?;
        Some(&self.disasm)
    }

    pub fn lift(&mut self, sleigh: &'_ SleighData) -> Result<&pcode::Block, LifterError> {
        self.lifter.lift(sleigh, &self.instruction)
    }

    pub fn get_instruction(&self) -> &Instruction {
        &self.instruction
    }
}

pub type TableId = u32;
pub type ConstructorId = u32;
pub type AttachmentId = u32;

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Token {
    /// Token could overwrite the global endian
    pub big_endian: bool,

    /// The offset of the token (in bytes) from the start of the byte stream.
    pub offset: u8,

    /// The size of the token in bytes.
    pub size: u8,
}

impl Token {
    /// Create a new token with a given size (in bytes) and endianness, with the offset set to zero.
    pub fn new(size: u8, big_endian: bool) -> Self {
        Self { offset: 0, size, big_endian }
    }

    /// Offset the token by `amount` bytes
    pub fn offset(self, amount: u8) -> Self {
        Self { offset: self.offset + amount, ..self }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Field {
    /// The bit offset of the field within the parent value.
    pub offset: u16,

    /// The size of the field in bits.
    pub num_bits: u16,

    /// Whether the field is signed.
    pub signed: bool,

    /// Whether the field should be displayed as a hexadecimal number.
    pub hex: bool,

    /// Any attached meaning to the field.
    pub attached: Option<AttachmentId>,
}

impl Field {
    /// Represents a field that is a constant `i64` value.
    pub fn i64() -> Self {
        Self { offset: 0, num_bits: 64, signed: true, hex: true, attached: None }
    }

    /// Extract and sign-extend the field from `value`.
    pub fn extract(&self, value: u64) -> i64 {
        let value = (value >> self.offset) & pcode::mask(self.num_bits as u64);
        match self.signed {
            true => pcode::sxt64(value, self.num_bits as u64) as i64,
            false => value as i64,
        }
    }

    /// Write the value of the field to `dst`.
    pub fn set(&self, dst: &mut u64, value: i64) {
        let mask = self.mask();
        *dst = (*dst & !mask) | (((value as u64) << self.offset) & mask);
    }

    /// Get a mask representing the bits that are read as part of `field`.
    pub fn mask(&self) -> u64 {
        pcode::mask(self.num_bits as u64) << self.offset
    }
}

#[derive(Debug, Copy, Clone)]
pub struct TokenField {
    /// The byte offset of the underlying token for this field.
    pub token_offset: u8,

    /// The number of bits in the underlying token for this field.
    pub token_bits: u8,

    /// Describes how the field is derived from the underlying token.
    pub field: Field,
}

impl TokenField {
    /// Offset the underlying token for this field by `amount` bytes
    pub fn offset(self, amount: u8) -> Self {
        Self { token_offset: self.token_offset + amount, ..self }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ContextField {
    /// Describes how the field is encoded within the context register.
    pub field: Field,
    /// Whether the context flows from the previous instruction to the next.
    pub flow: bool,
}

pub type StrIndex = (u32, u32);
pub type MatcherIndex = u32;
pub type LocalIndex = u32;
pub type SubtableIndex = u32;

/// Represents a group of constructors that are disambiguated by constraint expression.
pub struct Table {
    /// The index of the initial matcher to use.
    pub matcher: MatcherIndex,
}

pub struct Constructor {
    /// The ID of the table that this constructor belongs to.
    pub table: TableId,

    /// The mnemonic associated with the constructor.
    pub mnemonic: Option<StrIndex>,

    /// The range of decode actions to perform for this constructor.
    pub decode_actions: (u32, u32),

    /// The range of actions to perform after performing the initial decoding of the instruction.
    pub post_decode_actions: (u32, u32),

    /// Actions to perform as part of the display segment for this constructor.
    pub display: (u32, u32),

    /// The fields defined by the fields of the constructor or disassembly action expressions.
    pub fields: (u32, u32),

    /// The range of semantics evaluated when the constructor is built.
    pub semantics: (u32, u32),

    /// Whether the semantic section of this constructor uses a delay slot.
    pub delay_slot: bool,

    /// The number of subtables evaluated by this constructor.
    pub subtables: u32,

    /// The value exported by the table. Or `None` if the table has no export.
    pub export: Option<Export>,

    /// The temporaries used in the semantic section.
    pub temporaries: (u32, u32),

    /// The number of labels used in the semantic section.
    pub num_labels: u32,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum EvalKind {
    ContextField(Field),
    TokenField(Token, Field),
}

/// An action for the decoder to perform.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum DecodeAction {
    /// Modifies the context register.
    ModifyContext(Field, PatternExprRange),

    /// Globally saves a context value.
    SaveContext(Field),

    /// Evaluate the current value of a field and store it into a local.
    Eval(LocalIndex, EvalKind),

    /// Evaluate a subtable.
    Subtable(SubtableIndex, TableId),

    /// Adjust the start of byte stream by a given offset.
    NextToken(u8),

    /// Enter a new group of fields to decode.
    GroupStart,

    /// Exit a group of fields to decode.
    GroupEnd,

    /// Tell the decoder that the ending token offset of the next group of actions may need to be
    /// adjusted.
    ExpandStart,

    /// End the current group of actions, and adjust the ending token offset if necessary.
    ExpandEnd,
}

pub type RegId = u32;
pub type NamedRegIndex = u32;

#[derive(Default, Clone)]
pub struct NamedRegister {
    /// The name of the register.
    pub name: StrIndex,

    /// The register assigned by the runtime.
    pub var: pcode::VarNode,

    /// The offset of this register in the original SLEIGH specification.
    pub offset: u32,
}

impl NamedRegister {
    /// Get the varnode associated with a slice of the register. Handling cases where the VarId may
    /// change because of SIMD register splitting.
    pub fn get_var(
        &self,
        offset: pcode::VarOffset,
        size: pcode::VarSize,
    ) -> Option<pcode::VarNode> {
        if offset + size > self.var.size {
            return None;
        }

        let (id_offset, var_offset) = (offset / MAX_REG_SIZE, offset % MAX_REG_SIZE);
        // Ensure that the access doesn't overlap with multiple sub-registers.
        if var_offset + size > MAX_REG_SIZE {
            return None;
        }

        Some(
            pcode::VarNode::new(
                self.var.id + id_offset as i16,
                self.var.size - id_offset * MAX_REG_SIZE,
            )
            .slice(var_offset, size),
        )
    }
}

#[derive(Debug)]
pub struct RegisterAlias {
    /// The offset (in bytes) from the start of the full-register.
    pub offset: u16,
    /// The size of the subslice.
    pub size: u16,
    /// The name assigned to the subslice.
    pub name: StrIndex,
}

pub struct RegisterInfo {
    /// The name of the full-register used as a fallback if there is no exact match.
    pub name: StrIndex,

    /// The size (in bytes) of the full-register.
    pub size: u8,

    /// The offset of the full-register in the original SLEIGH specification.
    pub offset: u32,

    /// Specific names for sub-slices of the register.
    pub aliases: Vec<RegisterAlias>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplaySegment {
    Literal(StrIndex),
    Field(LocalIndex),
    Subtable(LocalIndex),
}

pub enum AttachmentIndex {
    Register((u32, u32), ValueSize),
    Name((u32, u32)),
    Value((u32, u32)),
}

#[derive(Clone, Copy)]
pub struct RegisterAttachment {
    pub name: StrIndex,
    pub offset: u32,
}

pub enum AttachmentRef<'a> {
    Name(&'a [StrIndex]),
    Value(&'a [i64]),
    Register(&'a [Option<RegisterAttachment>], ValueSize),
}

pub struct ConstructorDebugInfo {
    pub line: String,
}

#[derive(Default)]
pub struct DebugInfo {
    pub subtable_names: Vec<StrIndex>,
    pub constructors: Vec<ConstructorDebugInfo>,
}

impl DebugInfo {
    pub fn constructor_lines<'value: 'iter, 'iter>(
        &'value self,
        instruction: &'iter Instruction,
    ) -> impl Iterator<Item = &'value str> + 'iter {
        instruction.subtables.iter().map(move |c| self.constructors[c.id as usize].line.as_str())
    }
}

#[derive(Default)]
pub struct SleighData {
    pub strings: String,

    pub subtables: Vec<Table>,
    pub matchers: Vec<Matcher>,

    pub context_fields: Vec<ContextField>,
    /// An index for looking up context fields by name.
    pub context_field_mapping: HashMap<String, usize>,

    pub constructors: Vec<Constructor>,
    pub fields: Vec<Field>,
    pub decode_actions: Vec<DecodeAction>,
    pub context_disasm_expr: Vec<PatternExprOp<ContextModValue>>,
    pub post_decode_actions: Vec<(LocalIndex, PatternExprRange)>,
    pub disasm_exprs: Vec<PatternExprOp<DisasmConstantValue>>,
    pub display_segments: Vec<DisplaySegment>,
    pub semantics: Vec<SemanticAction>,
    pub temporaries: Vec<PcodeTmp>,

    pub attachments: Vec<AttachmentIndex>,
    pub attached_names: Vec<StrIndex>,
    pub attached_registers: Vec<Option<RegisterAttachment>>,
    pub attached_values: Vec<i64>,

    pub user_ops: Vec<StrIndex>,

    /// The entries in the register_space defined by the SLEIGH specification.
    pub named_registers: Vec<NamedRegister>,

    /// An index for looking up registers by name.
    pub register_name_mapping: HashMap<String, NamedRegIndex>,

    /// Registers that are grouped when overlapping.
    pub registers: Vec<RegisterInfo>,

    /// Instead of exposing a register_space/unique_space where values are index by an offset like
    /// Ghidra does, we instead map all global space offsets to local offsets within
    /// non-overlapping registers.
    pub register_mapping: HashMap<u32, (NamedRegIndex, pcode::VarOffset)>,

    /// Varnodes reserved for temporaries that live across internal block boundaries.
    pub saved_tmps: Vec<pcode::VarNode>,

    pub debug_info: DebugInfo,

    pub default_space_size: u16,
    pub alignment: u16,
    pub big_endian: bool,
}

impl SleighData {
    pub fn decode_into(&self, state: &mut Decoder, inst: &mut Instruction) -> Option<()> {
        state.decode_into(self, inst)
    }

    pub fn decode(&self, state: &mut Decoder) -> Option<Instruction> {
        let mut inst = Instruction::default();
        self.decode_into(state, &mut inst)?;
        Some(inst)
    }

    /// Disassembles the previously decoded `inst` storing the result in `disasm`.
    ///
    /// Returns `None` if the instruction is invalid.
    pub fn disasm_into(&self, inst: &Instruction, disasm: &mut String) -> Option<()> {
        crate::disasm::disasm_subtable(inst.root(self), disasm)
    }

    /// Disassembles the previously decoded `inst` as a string. The same as `self.disasm_into` but
    /// always allocates and returns a new string.
    pub fn disasm(&self, inst: &Instruction) -> Option<String> {
        let mut disasm = String::new();
        self.disasm_into(inst, &mut disasm)?;
        Some(disasm)
    }

    /// if `Name` is none,
    pub fn register_user_op(&mut self, name: Option<&str>) -> pcode::HookId {
        let id = self.user_ops.len();
        let before_strs = self.strings.len();
        if let Some(name) = name {
            self.strings.push_str(name);
        }
        self.user_ops.push((before_strs as u32, self.strings.len() as u32));
        id.try_into().expect("too many user ops")
    }

    /// Returns an iterater over of all user/pcode operations
    pub fn get_user_ops(&self) -> impl Iterator<Item = &str> + '_ {
        self.user_ops.iter().map(move |i| self.get_str(*i))
    }

    /// Get the ID associated with a userop of a given name.
    pub fn get_userop(&self, name: &str) -> Option<pcode::HookId> {
        // @fixme: avoid sequential scan
        self.user_ops.iter().position(|x| self.get_str(*x) == name).map(|x| x as pcode::HookId)
    }

    /// Lookup a context field
    pub fn get_context_field(&self, name: &str) -> Option<ContextField> {
        self.context_field_mapping.get(name).map(|x| self.context_fields[*x as usize])
    }

    /// Get the register for a given name.
    pub fn get_reg(&self, name: &str) -> Option<&NamedRegister> {
        self.register_name_mapping.get(name).map(|x| &self.named_registers[*x as usize])
    }

    /// Given a runtime varnode, attempt to find the best matching register name from the original
    /// SLEIGH specification.
    pub fn name_of_varnode(&self, var: pcode::VarNode) -> Option<&str> {
        let reg = self.registers.get(var.id as usize)?;
        if var.offset == 0 && var.size == reg.size {
            return Some(self.get_str(reg.name));
        }
        reg.aliases
            .iter()
            .find(|alias| var.offset as u16 == alias.offset && var.size as u16 == alias.size)
            .map(|alias| self.get_str(alias.name))
    }

    /// Add a custom register.
    ///
    /// Returns `None` if a register with the same name already exists.
    pub fn add_custom_reg(&mut self, name: &str, size: u8) -> Option<pcode::VarNode> {
        if self.register_name_mapping.contains_key(name) {
            // Register with the same name already exists.
            return None;
        }

        let named_reg_id = self.named_registers.len().try_into().unwrap();
        self.register_name_mapping.insert(name.to_owned(), named_reg_id);

        let name = self.add_string(name);
        let id = self.registers.len().try_into().unwrap();
        self.registers.push(RegisterInfo { name, size, offset: 0xfff000, aliases: vec![] });

        let var = pcode::VarNode::new(id, size);
        self.named_registers.push(NamedRegister { name, var, offset: 0xfff000 });

        Some(var)
    }

    /// Maps a SLEIGH register to an internal VarNode ID and offset.
    pub fn map_sleigh_reg(&self, offset: u32, size: u8) -> Option<(&NamedRegister, u8)> {
        let &(idx, varnode_offset) = self.register_mapping.get(&offset)?;
        let parent_reg = &self.named_registers[idx as usize];
        if varnode_offset + size > parent_reg.var.size {
            // Attempted to access bytes outside of the register.
            return None;
        }
        Some((parent_reg, varnode_offset))
    }

    #[inline]
    pub fn num_registers(&self) -> usize {
        self.registers.len()
    }

    /// Returns a reference to the content of the interned string given by `index`.
    pub fn get_str(&self, index: StrIndex) -> &str {
        &self.strings[index.0 as usize..index.1 as usize]
    }

    pub fn get_attachment(&self, id: AttachmentId) -> AttachmentRef {
        match &self.attachments[id as usize] {
            AttachmentIndex::Register((start, end), size) => {
                let regs = &self.attached_registers[*start as usize..*end as usize];
                AttachmentRef::Register(regs, *size)
            }
            AttachmentIndex::Name((start, end)) => {
                AttachmentRef::Name(&self.attached_names[*start as usize..*end as usize])
            }
            AttachmentIndex::Value((start, end)) => {
                AttachmentRef::Value(&self.attached_values[*start as usize..*end as usize])
            }
        }
    }

    /// Finds a matching constructor given the current decoder state using the matcher `matcher_id`.
    /// On a match, returns the constructor ID of the matching constructor, and the offset of the
    /// _next_ case to match to use for backtracking.
    fn match_constructor_with(
        &self,
        state: &Decoder,
        matcher_id: MatcherIndex,
        offset: usize,
    ) -> Option<(ConstructorId, usize)> {
        self.matchers[matcher_id as usize].match_constructor(state, offset)
    }

    pub fn get_context_mod_expr(
        &self,
        expr: PatternExprRange,
    ) -> &[PatternExprOp<ContextModValue>] {
        &self.context_disasm_expr[expr.0 as usize..expr.1 as usize]
    }

    pub fn get_disasm_expr(&self, expr: PatternExprRange) -> &[PatternExprOp<DisasmConstantValue>] {
        &self.disasm_exprs[expr.0 as usize..expr.1 as usize]
    }
}

impl SleighData {
    /// Interns the string `value`, returning an index that can later be used to retreive the
    /// string.
    pub fn add_string(&mut self, value: &str) -> StrIndex {
        let index = self.strings.len();
        self.strings.push_str(value);
        (index as u32, self.strings.len() as u32)
    }

    /// Interns all of `segments`, returning that can later be used to retreive the segments.
    pub fn add_display_segments(&mut self, segments: &[DisplaySegment]) -> (u32, u32) {
        let start = self.display_segments.len() as u32;
        self.display_segments.extend(segments);
        let end = self.display_segments.len() as u32;
        (start, end)
    }
}

impl pcode::PcodeDisplay<SleighData> for pcode::VarNode {
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &SleighData) -> std::fmt::Result {
        let reg_info = match ctx.registers.get(self.id as usize) {
            Some(info) => info,
            None => return self.display(&()).fmt(f),
        };

        if let Some(alias) = reg_info
            .aliases
            .iter()
            .find(|alias| self.offset as u16 == alias.offset && self.size as u16 == alias.size)
        {
            return f.write_str(ctx.get_str(alias.name));
        }

        match self.offset {
            0 if self.size == reg_info.size => f.write_str(ctx.get_str(reg_info.name)),
            0 => write!(f, "{}:{}", ctx.get_str(reg_info.name), self.size),
            offset => write!(f, "{}[{}]:{}", ctx.get_str(reg_info.name), offset, self.size),
        }
    }
}

impl pcode::PcodeDisplay<SleighData> for pcode::UserOpId {
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &SleighData) -> std::fmt::Result {
        match ctx.user_ops.get(self.0 as usize) {
            Some(range) => f.write_str(ctx.get_str(*range)),
            None => write!(f, "pcode_op<{}>", self.0),
        }
    }
}

impl pcode::PcodeDisplay<SleighData> for pcode::SpaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter, _: &SleighData) -> std::fmt::Result {
        // @todo: support names for other address spaces.
        match self.0 {
            pcode::RAM_SPACE => f.write_str("ram"),
            pcode::REGISTER_SPACE => f.write_str("register"),
            pcode::RESERVED_SPACE_END.. => write!(f, "mem.{}", self.0),
        }
    }
}
