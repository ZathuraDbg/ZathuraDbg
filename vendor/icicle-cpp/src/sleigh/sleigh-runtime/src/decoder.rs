use crate::{
    semantics::{PcodeTmp, SemanticAction},
    Constructor, DecodeAction, DisplaySegment, EvalKind, LocalIndex, SleighData, DEBUG,
    ROOT_TABLE_ID,
};

use crate::{
    expr::{eval_pattern_expr, EvalPatternValue, PatternExprRange},
    ConstructorId, Field, TableId, Token,
};

/// The decoder context for the current instruction.
pub struct Decoder {
    /// The global decoder context.
    pub global_context: u64,

    /// The local context value.
    pub(crate) context: u64,

    /// The bytes in the instruction stream.
    bytes: Vec<u8>,

    /// Configures whether token fields should be decoded as big endian.
    big_endian: bool,

    /// Controls whether backtracking is allowed during instruction decoding. Required for some
    /// specifications, however results in a performance penalty in some cases.
    ///
    /// @todo: Currently there is no way of disabling this from the external API.
    pub(crate) allow_backtracking: bool,

    /// Controls whether to ignore delayslots.
    pub(crate) ignore_delay_slots: bool,

    /// Controls the maximum number of subtables the decoder will attempt to resolve before
    /// bailing. Catches unbounded recursion in SLEIGH specifications.
    max_subtables: usize,

    /// Keeps track of whether the current instruction is valid.
    is_valid: bool,

    /// The base address of the instruction stream.
    base_addr: u64,

    /// The offset of the current token in instruction stream.
    offset: usize,

    /// The offset of the next token in instruction stream.
    next_offset: usize,

    /// The stack of token offsets for storing parent token positions.
    token_stack: Vec<(usize, usize)>,

    /// A stack for storing intermediate values used for evaluating expressions.
    eval_stack: Vec<i64>,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            global_context: 0,
            context: 0,
            bytes: Vec::new(),
            big_endian: false,
            allow_backtracking: true,
            ignore_delay_slots: false,
            max_subtables: 64,
            is_valid: false,
            base_addr: 0,
            offset: 0,
            next_offset: 0,
            token_stack: Vec::new(),
            eval_stack: Vec::new(),
        }
    }
    pub fn set_inst(&mut self, base_addr: u64, bytes: &[u8]) {
        self.context = self.global_context;
        self.base_addr = base_addr;
        self.offset = 0;
        self.next_offset = 0;
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
    }

    /// Decode the current instruction storing the result in `inst`.
    pub fn decode_into(&mut self, sleigh: &SleighData, inst: &mut Instruction) -> Option<()> {
        self.is_valid = true;

        // Clear any noflow fields from `global_context`
        for entry in sleigh.context_fields.iter().filter(|entry| !entry.flow) {
            entry.field.set(&mut self.global_context, 0);
        }

        self.big_endian = sleigh.big_endian;
        let root = inst.init();

        let constructor = self.decode_subtable(sleigh, inst, ROOT_TABLE_ID);
        inst.subtables[root as usize] = constructor;

        inst.root_mut(sleigh).eval_disasm_expr(self);

        // Delay slots need to be decoded _before_ the semantic section is evaluated because the
        // specification requires that `inst_next` refers to the address after the delay slot.
        //
        // Note: this differs from the behaviour of the disassembly section, where `inst_next`
        // refers to the address immediately after the first instruction.
        if let Some(_) = inst.delay_slot {
            self.offset = self.next_offset;
            if !self.ignore_delay_slots {
                inst.delay_slot = Some(self.decode_subtable(sleigh, inst, ROOT_TABLE_ID));
            }
            else {
                // Assume the size of the delay slot is the same as the root instruction.
                self.next_offset *= 2;
                inst.delay_slot = Some(invalid_constructor(sleigh));
            }
        }

        inst.inst_start = self.base_addr;
        inst.inst_next = self.base_addr + self.next_offset as u64;

        if !self.is_valid {
            return None;
        }

        Some(())
    }

    fn decode_subtable(
        &mut self,
        sleigh: &SleighData,
        inst: &mut Instruction,
        table: TableId,
    ) -> DecodedConstructor {
        if inst.subtables.len() > self.max_subtables {
            self.is_valid = false;
            return invalid_constructor(sleigh);
        }

        // The offset next constructor to match, used to resume the search at the correct position
        // after backtracking.
        let mut match_offset = 0;

        // Keep track of the current state before we try to the decode the first matching
        // constructor, so we correct the state if we need to backtrack.
        let initial_offset = self.offset;
        let initial_next_offset = self.next_offset;
        let initial_context = self.context;
        let initial_global_context = self.global_context;
        let initial_token_stack_len = self.token_stack.len();

        while let Some((constructor_id, next_match_offset)) =
            sleigh.match_constructor_with(self, table, match_offset)
        {
            if let Some(constructor) = self.try_decode_constructor(sleigh, inst, constructor_id) {
                if self.is_valid || !self.allow_backtracking {
                    return constructor;
                }
            }

            // Failed to decode current constructor, backtrack and try again.
            if !self.allow_backtracking {
                break;
            }
            self.is_valid = true;
            match_offset = next_match_offset;
            self.offset = initial_offset;
            self.next_offset = initial_next_offset;
            self.token_stack.truncate(initial_token_stack_len);
            self.context = initial_context;
            self.global_context = initial_global_context;
        }

        // Failed to find any matching constructor. Record last subtable searched to aid debugging.
        inst.last_subtable = table;
        self.is_valid = false;
        invalid_constructor(sleigh)
    }

    fn try_decode_constructor(
        &mut self,
        sleigh: &SleighData,
        inst: &mut Instruction,
        constructor_id: ConstructorId,
    ) -> Option<DecodedConstructor> {
        let mut ctx = inst.alloc_constructor(sleigh, constructor_id).ok()?;
        ctx.constructor.offset = self.offset as u8;

        let mut next = self.next_offset;

        if DEBUG {
            let line = &sleigh.debug_info.constructors[constructor_id as usize].line;
            eprintln!(
                "constructor={line} (id={constructor_id}), offset={}, next={next} actions={:?}",
                self.offset,
                ctx.as_ref().decode_actions()
            );
        }

        self.next_offset = self.offset;
        for action in ctx.as_ref().decode_actions() {
            match action {
                DecodeAction::ModifyContext(field, expr) => {
                    let value = self.eval_context_expr(*expr, sleigh);
                    field.set(&mut self.context, value);
                }
                DecodeAction::SaveContext(field) => {
                    let value = field.extract(self.context);
                    field.set(&mut self.global_context, value);
                }
                DecodeAction::Eval(idx, kind) => {
                    ctx.locals_mut()[*idx as usize] = match kind {
                        EvalKind::ContextField(field) => field.extract(self.context),
                        EvalKind::TokenField(token, field) => field.extract(self.get_token(*token)),
                    };
                }
                DecodeAction::Subtable(idx, id) => {
                    let constructor = self.decode_subtable(sleigh, ctx.inst, *id);
                    if !self.is_valid && self.allow_backtracking {
                        // If there was no valid constructor for this subtable and we allow
                        // backtracking, then exit here and backtrack. If backtracking is disabled,
                        // then this must be an invalid instruction, but we continue with decoding
                        // to provide a partial decoding for debugging.
                        return None;
                    }
                    ctx.subtables_mut()[*idx as usize] = constructor;
                }
                DecodeAction::NextToken(size) => {
                    // Most of the time the sleigh spec uses explicit expand tokens (i.e. `...`) to
                    // handle the case where a previous token expands to a longer token, however the
                    // MSP430X spec seems not to do this (e.g. `MOVX.W &0, R10`).
                    //
                    // To work around this we always perform an implicit `...` on every token.
                    //
                    //@todo: check this behaviour.
                    next = next.max(self.next_offset);
                    self.next_offset = self.next_offset.max(self.offset + *size as usize);
                }
                DecodeAction::GroupStart => {
                    // Save current token position and step to next offset.
                    self.token_stack.push((self.offset, self.next_offset));
                    self.offset = self.next_offset;
                }
                DecodeAction::GroupEnd => {
                    // Implicit `...` (see `NextToken` above).
                    next = next.max(self.next_offset);
                    // Restore previous token position.
                    (self.offset, self.next_offset) = self.token_stack.pop().unwrap();
                }
                DecodeAction::ExpandStart => {}
                DecodeAction::ExpandEnd => {}
            }
        }
        self.next_offset = next.max(self.next_offset);
        ctx.constructor.len = (self.next_offset - ctx.constructor.offset as usize) as u8;

        Some(ctx.constructor)
    }

    fn eval_context_expr(&mut self, expr: PatternExprRange, sleigh: &SleighData) -> i64 {
        let mut stack = std::mem::take(&mut self.eval_stack);
        let expr = sleigh.get_context_mod_expr(expr);
        let result =
            eval_pattern_expr(&mut stack, &*self, expr).expect("invalid disassembly expression");
        self.eval_stack = stack;
        result
    }

    /// Read a raw token (i.e. without any endianness conversion) of `token_size` bytes, from the
    /// instruction stream at `offset`.
    ///
    /// Note: The instruction stream is padded with zeros.
    #[inline]
    pub fn get_raw_token(&self, token_offset: usize, token_size: usize) -> u64 {
        let start = token_offset + self.offset;
        let end = (start + token_size).min(self.bytes.len());

        match self.bytes.get(start..end) {
            Some(bytes) => {
                let mut buf = [0; 8];
                buf[..bytes.len()].copy_from_slice(bytes);
                u64::from_le_bytes(buf)
            }
            None => 0,
        }
    }

    /// Read a token from the instruction stream.
    pub(crate) fn get_token(&self, token: Token) -> u64 {
        // Macro for specialized token sizes.
        macro_rules! read_token {
            ($ty:ty) => {{
                let start = token.offset as usize + self.offset;
                match self.bytes.get(start..start + std::mem::size_of::<$ty>()) {
                    Some(bytes) => {
                        let array = bytes.try_into().unwrap();
                        match token.big_endian {
                            true => <$ty>::from_be_bytes(array) as u64,
                            false => <$ty>::from_le_bytes(array) as u64,
                        }
                    }
                    None => 0,
                }
            }};
        }

        match token.size as usize {
            1 => read_token!(u8),
            2 => read_token!(u16),
            4 => read_token!(u32),
            8 => read_token!(u64),
            x if x < 8 => {
                let mut raw_token =
                    self.get_raw_token(token.offset.into(), token.size.into()).to_le_bytes();
                if token.big_endian {
                    raw_token[..x].reverse();
                }
                u64::from_le_bytes(raw_token)
            }
            _ => panic!("invalid token size: {}", token.size),
        }
    }
}

fn invalid_constructor(sleigh: &SleighData) -> DecodedConstructor {
    DecodedConstructor {
        id: (sleigh.constructors.len() - 1) as u32,
        locals: (0, 0),
        subtables: (0, 0),
        offset: 0,
        len: 0,
    }
}

pub type LocalsSlice = (u32, u32);
pub type SubtablesSlice = (u32, u32);

#[derive(Debug, Default, Clone)]
pub struct Instruction {
    /// The values of local fields references by the instruction.
    pub(crate) locals: Vec<i64>,

    /// The decoded constructors for each subtable reference by the instruction including subtables
    /// referenced by a potential delay slot.
    pub subtables: Vec<DecodedConstructor>,

    /// The root level constructor for the instruction in the delay slot (if present).
    pub delay_slot: Option<DecodedConstructor>,

    /// The address of the instruction.
    pub inst_start: u64,

    /// The address of the next instruction.
    pub inst_next: u64,

    /// Keeps track of the last subtable that we failed to find a constructor for.
    pub last_subtable: u32,
}

impl Instruction {
    pub fn init(&mut self) -> u32 {
        self.locals.clear();
        self.subtables.clear();
        self.delay_slot = None;
        self.last_subtable = 0;
        self.reserve_subtables(1).0
    }

    /// Returns whether the current instruction contains a delayslot.
    pub fn has_delay_slot(&self) -> bool {
        self.delay_slot.is_some()
    }

    /// Returns the length of the instruction in bytes.
    pub fn num_bytes(&self) -> u64 {
        self.inst_next.checked_sub(self.inst_start).unwrap_or(0)
    }

    /// Reserve `count` local parameters, returning the range of the reserved parameters.
    fn reserve_locals(&mut self, count: u32) -> LocalsSlice {
        let start = self.locals.len();
        self.locals.resize(start + count as usize, 0);
        (start as u32, self.locals.len() as u32)
    }

    /// Reserve `count` subtables, returning the range of the reserved subtables.
    fn reserve_subtables(&mut self, count: u32) -> SubtablesSlice {
        let start = self.subtables.len();
        self.subtables.resize(start + count as usize, DecodedConstructor::default());
        (start as u32, self.subtables.len() as u32)
    }

    fn alloc_constructor<'a, 'b>(
        &'a mut self,
        data: &'b SleighData,
        id: ConstructorId,
    ) -> Result<SubtableCtxMut<'a, 'b>, ()> {
        let constructor = &data.constructors[id as usize];

        if constructor.delay_slot {
            if self.delay_slot.is_some() {
                // @todo: return a proper error message.
                eprintln!("[sleigh]: Nested delay slots are not allowed");
                return Err(());
            }
            self.delay_slot = Some(DecodedConstructor::default());
        }

        let locals = self.reserve_locals(constructor.fields.1 - constructor.fields.0);
        let subtables = self.reserve_subtables(constructor.subtables);
        Ok(SubtableCtxMut {
            inst: self,
            data,
            constructor: DecodedConstructor { id, locals, subtables, offset: 0, len: 0 },
        })
    }

    fn subtable<'a, 'b>(&'a self, data: &'b SleighData, idx: u32) -> SubtableCtx<'a, 'b> {
        let constructor = self.subtables[idx as usize];
        SubtableCtx { inst: self, data, constructor }
    }

    pub fn root_mut<'a, 'b>(&'a mut self, data: &'b SleighData) -> SubtableCtxMut<'a, 'b> {
        let constructor = self.subtables[0];
        SubtableCtxMut { inst: self, data, constructor }
    }

    pub fn root<'a, 'b>(&'a self, data: &'b SleighData) -> SubtableCtx<'a, 'b> {
        self.subtable(data, 0)
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct DecodedConstructor {
    /// The ID of the constructor.
    pub id: ConstructorId,

    /// The range of local fields defined by the constructor.
    pub locals: LocalsSlice,

    /// The range of subtable fields defined by the constructor.
    pub subtables: SubtablesSlice,

    /// Byte offset of the decoded constructor from the start of the instruction.
    pub offset: u8,

    /// Length (in bytes) of the constructor.
    pub len: u8,
}

pub struct SubtableCtx<'a, 'b> {
    pub(crate) data: &'b SleighData,
    pub(crate) inst: &'a Instruction,
    pub(crate) constructor: DecodedConstructor,
}

impl std::ops::Deref for SubtableCtx<'_, '_> {
    type Target = Instruction;

    fn deref(&self) -> &Self::Target {
        self.inst
    }
}

impl<'a, 'b> SubtableCtx<'a, 'b> {
    pub fn visit_constructor(&self, constructor: DecodedConstructor) -> Self {
        SubtableCtx { data: self.data, inst: self.inst, constructor }
    }

    pub fn constructor_info(&self) -> &'b Constructor {
        &self.data.constructors[self.constructor.id as usize]
    }

    pub fn decode_actions(&self) -> &'b [DecodeAction] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].decode_actions;
        &self.data.decode_actions[start as usize..end as usize]
    }

    pub fn post_decode_actions(&self) -> &'b [(LocalIndex, PatternExprRange)] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].post_decode_actions;
        &self.data.post_decode_actions[start as usize..end as usize]
    }

    pub fn display_segments(&self) -> &'b [DisplaySegment] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].display;
        &self.data.display_segments[start as usize..end as usize]
    }

    pub fn fields(&self) -> &'b [Field] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].fields;
        &self.data.fields[start as usize..end as usize]
    }

    pub fn locals(&self) -> &[i64] {
        &self.inst.locals[self.constructor.locals.0 as usize..self.constructor.locals.1 as usize]
    }

    pub fn subtables(&self) -> &[DecodedConstructor] {
        &self.inst.subtables
            [self.constructor.subtables.0 as usize..self.constructor.subtables.1 as usize]
    }

    pub fn semantics(&self) -> &'b [SemanticAction] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].semantics;
        &self.data.semantics[start as usize..end as usize]
    }

    pub fn temporaries(&self) -> &[PcodeTmp] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].temporaries;
        &self.data.temporaries[start as usize..end as usize]
    }

    /// Extends `output` with the constructor IDs referenced in the order they are visited in.
    pub fn append_visited_constructors(&self, output: &mut Vec<ConstructorId>) {
        output.push(self.constructor.id);
        for subtable in self.subtables() {
            self.visit_constructor(*subtable).append_visited_constructors(output);
        }
    }
}

pub struct SubtableCtxMut<'a, 'b> {
    pub(crate) data: &'b SleighData,
    pub(crate) inst: &'a mut Instruction,
    pub(crate) constructor: DecodedConstructor,
}

impl std::ops::Deref for SubtableCtxMut<'_, '_> {
    type Target = Instruction;

    fn deref(&self) -> &Self::Target {
        self.inst
    }
}

impl std::ops::DerefMut for SubtableCtxMut<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inst
    }
}

impl<'a, 'b> SubtableCtxMut<'a, 'b> {
    fn as_ref(&'a self) -> SubtableCtx<'a, 'b> {
        SubtableCtx { data: self.data, inst: self.inst, constructor: self.constructor }
    }

    pub fn visit_constructor(&mut self, constructor: DecodedConstructor) -> SubtableCtxMut<'_, 'b> {
        SubtableCtxMut { data: self.data, inst: self.inst, constructor }
    }

    fn eval_disasm_expr(&mut self, state: &mut Decoder) {
        for subtable in self.constructor.subtables.0..self.constructor.subtables.1 {
            let constructor = self.inst.subtables[subtable as usize];
            let mut ctx = SubtableCtxMut { data: self.data, inst: self.inst, constructor };
            ctx.eval_disasm_expr(state);
        }

        for (local, expr) in self.as_ref().post_decode_actions() {
            let mut stack = std::mem::take(&mut state.eval_stack);

            let value = eval_pattern_expr(
                &mut stack,
                DisasmLocalEval { state, ctx: self.as_ref() },
                self.data.get_disasm_expr(*expr),
            )
            .expect("invalid disasm expr");
            self.locals_mut()[*local as usize] = value;

            state.eval_stack = stack;
        }
    }

    fn locals_mut(&mut self) -> &mut [i64] {
        &mut self.inst.locals
            [self.constructor.locals.0 as usize..self.constructor.locals.1 as usize]
    }

    fn subtables_mut(&mut self) -> &mut [DecodedConstructor] {
        &mut self.inst.subtables
            [self.constructor.subtables.0 as usize..self.constructor.subtables.1 as usize]
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ContextModValue {
    TokenField(Token, Field),
    ContextField(Field),
    InstStart,
}

impl EvalPatternValue for &'_ Decoder {
    type Value = ContextModValue;

    fn eval(&self, value: &Self::Value) -> i64 {
        match value {
            ContextModValue::ContextField(field) => field.extract(self.context),
            ContextModValue::TokenField(token, field) => field.extract(self.get_token(*token)),
            ContextModValue::InstStart => self.base_addr as i64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DisasmConstantValue {
    LocalField(u32),
    ContextField(Field),
    InstStart,
    InstNext,
}

struct DisasmLocalEval<'a, 'b, 'c> {
    state: &'c Decoder,
    ctx: SubtableCtx<'a, 'b>,
}

impl EvalPatternValue for DisasmLocalEval<'_, '_, '_> {
    type Value = DisasmConstantValue;

    fn eval(&self, value: &Self::Value) -> i64 {
        match value {
            DisasmConstantValue::LocalField(idx) => self.ctx.locals()[*idx as usize],
            DisasmConstantValue::ContextField(field) => field.extract(self.state.context),
            DisasmConstantValue::InstStart => self.state.base_addr as i64,
            DisasmConstantValue::InstNext => {
                (self.state.base_addr + self.state.next_offset as u64) as i64
            }
        }
    }
}
