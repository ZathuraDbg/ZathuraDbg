use std::{collections::HashMap, usize};

use sleigh_parse::{
    ast,
    ast::{EndianKind, ParserDisplay},
};
use sleigh_runtime::{semantics::ValueSize, Field};

use crate::{constructor::Constructor, Context};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SymbolKind {
    Space,
    Register,
    Token,
    TokenField,
    ContextField,
    BitRange,
    Table,
    Macro,
    UserOp,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct Symbol {
    pub kind: SymbolKind,
    pub id: u32,
}

pub type SpaceId = u32;
pub type RegisterId = u32;
pub type _BitRangeId = u32;
pub type TokenId = u32;
pub type TokenFieldId = u32;
pub type TableId = u32;
pub type ConstructorId = u32;
pub type _MacroId = u32;
pub type _UserOpId = u32;

pub(crate) struct SymbolTable {
    pub endianness: ast::EndianKind,

    pub spaces: Vec<RamSpace>,
    pub registers: Vec<Register>,
    pub bit_ranges: Vec<BitRange>,
    pub context_fields: Vec<ContextField>,
    pub tokens: Vec<Token>,
    pub token_fields: Vec<TokenField>,
    pub attachments: Vec<Attachment>,
    pub tables: Vec<Table>,
    pub constructors: Vec<Constructor>,
    pub macros: Vec<Macro>,
    pub user_ops: Vec<ast::Ident>,
    pub default_space: Option<SpaceId>,
    pub debug_info: HashMap<u32, SourceFile>,

    pub mapping: HashMap<ast::Ident, Symbol>,
    pub inst_next_ident: ast::Ident,
    pub inst_start_ident: ast::Ident,
    pub epsilon_ident: ast::Ident,
    pub root_table_ident: ast::Ident,
    pub const_ident: ast::Ident,
    pub delay_slot_ident: ast::Ident,
    pub register_space_ident: ast::Ident,
    pub placeholder_ident: ast::Ident,

    pub parser: sleigh_parse::Parser,
}

impl SymbolTable {
    pub(crate) fn new(mut parser: sleigh_parse::Parser) -> Self {
        let inst_next_ident = parser.get_ident("inst_next");
        let inst_start_ident = parser.get_ident("inst_start");
        let epsilon_ident = parser.get_ident("epsilon");
        let root_table_ident = parser.get_ident("instruction");
        let const_ident = parser.get_ident("const");
        let delay_slot_ident = parser.get_ident("delayslot");
        let register_space_ident = parser.get_ident("register");

        // `_` is used as a placeholder identifier used for skipping fields
        let placeholder_ident = parser.get_ident("_");

        let mut symbols = Self {
            endianness: EndianKind::Little,
            spaces: Default::default(),
            registers: Default::default(),
            bit_ranges: Default::default(),
            context_fields: Default::default(),
            tokens: Default::default(),
            token_fields: Default::default(),
            attachments: Default::default(),
            tables: Default::default(),
            constructors: Default::default(),
            macros: Default::default(),
            user_ops: Default::default(),
            mapping: Default::default(),
            default_space: Default::default(),
            debug_info: Default::default(),

            inst_next_ident,
            inst_start_ident,
            epsilon_ident,
            root_table_ident,
            const_ident,
            delay_slot_ident,
            register_space_ident,
            placeholder_ident,

            parser,
        };

        // In order to support instruction prefixes, Sleigh supports referencing the root level
        // table (`instruction`) before it is declared. So we define it ahead of time here.
        symbols.define_table(root_table_ident).unwrap();

        // Add debug info to the symbol table.
        for (id, source) in symbols.parser.sources.iter().enumerate() {
            symbols.debug_info.insert(id as u32, SourceFile {
                name: source.name.clone(),
                lines: source.lines.clone(),
            });
        }

        symbols
    }
}

/// A macro for simultaneously inserting a value into the symbol table, and mapping its index to an
/// identifier
macro_rules! insert_and_map {
    ($self:expr, $field:ident, $ident:expr, $kind:expr, $value:expr) => {{
        let id = ($self.$field.len()).try_into().unwrap();
        $self.$field.push($value);
        $self.map_symbol($ident, Symbol { kind: $kind, id })
    }};
}

impl SymbolTable {
    /// Return the symbol associated with `name` or an error if it was not found in the symbol table
    pub fn lookup(&self, ident: ast::Ident) -> Result<Symbol, String> {
        Ok(*self
            .mapping
            .get(&ident)
            .ok_or_else(|| format!("undefined symbol: {}", ident.display(&self.parser)))?)
    }

    /// Return the symbol id associated with `name` of type `kind` returning an error if was not
    /// found in the symbol table or if the resolved symbol was the wrong kind.
    pub fn lookup_kind(&self, ident: ast::Ident, kind: SymbolKind) -> Result<u32, String> {
        let sym = self.lookup(ident)?;
        if sym.kind != kind {
            let name = ident.display(&self.parser);
            return Err(format!("{:?}<{}> is not a {:?}", sym.kind, name, kind));
        }
        Ok(sym.id)
    }

    /// Checks whether the symbol `ident` exists in the symbol table
    pub fn contains(&self, ident: ast::Ident) -> bool {
        self.mapping.contains_key(&ident)
    }

    /// Maps `ident` to `symbol`, returning an error if `ident` was previously defined.
    pub fn map_symbol(&mut self, ident: ast::Ident, symbol: Symbol) -> Result<Symbol, String> {
        if self.mapping.insert(ident, symbol).is_some() {
            // @todo: propagate span information
            return Err(format!("redeclaration of symbol: {}", ident.display(&self.parser)));
        }
        Ok(symbol)
    }

    /// Handles a space defintion.
    ///
    /// Returns an error if:
    ///  - The new space is defined as the default space, but a default space was previously
    ///    defined.
    ///  - The space is a ROM space (ROM spaces are currently unsupported).
    ///  - The name of the space overlaps with an existing identifier.
    pub fn define_space(&mut self, space: ast::Space) -> Result<(), String> {
        let id = match space.kind {
            ast::SpaceKind::RamSpace => pcode::RAM_SPACE,
            ast::SpaceKind::RegisterSpace => pcode::REGISTER_SPACE,
            ast::SpaceKind::RomSpace => return Err("only ROM space not supported".into()),
        };

        let sym = insert_and_map!(self, spaces, space.name, SymbolKind::Space, RamSpace {
            space_id: id,
            size: space.size,
            word_size: space.word_size.unwrap_or(1),
        })?;

        if space.default {
            if self.default_space.is_some() {
                return Err("multiple default spaces".into());
            }
            self.default_space = Some(sym.id);
        }

        Ok(())
    }

    /// Handles the association of identifiers to VarNodes within a space.
    ///
    /// Returns an error if the space is not the `register` space (defining names for VarNodes in
    /// other spaces is not currently supported), or if any identifier overlaps with an existing
    /// identifier.
    pub fn define_register_names(&mut self, def: ast::SpaceNameDef) -> Result<(), String> {
        if def.space != self.register_space_ident {
            return Err("Can only name offsets within a register_space".into());
        }

        for (i, ident) in def.names.into_iter().enumerate() {
            if ident == self.placeholder_ident {
                continue;
            }

            // Each entry within the list is offset by its position in the list
            let offset = (def.offset + (i as u64 * def.size as u64)).try_into().unwrap();
            insert_and_map!(self, registers, ident, SymbolKind::Register, Register {
                name: ident,
                offset,
                size: def.size,
            })?;
        }

        Ok(())
    }

    /// Handles the definition of a named bitrange within a register.
    ///
    /// Returns an error if the register specified for the range does not exist, or the name of the
    /// bitrange overlaps with an existing identifier.
    pub fn define_bitrange(&mut self, value: ast::BitRange) -> Result<(), String> {
        let register = self.lookup_kind(value.source, SymbolKind::Register)?;
        insert_and_map!(self, bit_ranges, value.name, SymbolKind::BitRange, BitRange {
            register,
            range: value.range,
        })?;
        Ok(())
    }

    /// Handles the definition of a context field
    pub fn define_context(&mut self, ctx: ast::Context) -> Result<(), String> {
        let register = self.lookup_kind(ctx.name, SymbolKind::Register)?;
        let register_bits = self.registers[register as usize].size * 8;

        for field in ctx.fields {
            let (offset, num_bits) = inverted_field_range(field.range, register_bits);
            insert_and_map!(
                self,
                context_fields,
                field.name,
                SymbolKind::ContextField,
                ContextField {
                    register,
                    name: field.name,
                    field: Field {
                        offset,
                        num_bits,
                        signed: field.signed,
                        hex: field.hex || (!field.dec),
                        attached: None
                    },
                    flow: !field.noflow,
                }
            )?;
        }
        Ok(())
    }

    /// Define a user/pcodeop. returns an error if the identifier has already been defined.
    pub fn define_userop(&mut self, ident: ast::Ident) -> Result<(), String> {
        insert_and_map!(self, user_ops, ident, SymbolKind::UserOp, ident)?;
        Ok(())
    }

    /// Handle a token (with token fields) definition.
    ///
    /// Returns an error if the identifier of the token or any of its fields has already been
    /// defined.
    pub fn define_token(&mut self, token: ast::TokenDef) -> Result<(), String> {
        let big_endian = token.endian.map(|endian| endian == EndianKind::Big);
        let num_bits =
            token.bits.try_into().map_err(|_| format!("token too large: {}", token.bits))?;
        let token_sym = insert_and_map!(self, tokens, token.name, SymbolKind::Token, Token {
            num_bits,
            big_endian,
        })?;

        for field in token.fields {
            let (offset, num_bits) = field_range(field.range);
            insert_and_map!(self, token_fields, field.name, SymbolKind::TokenField, TokenField {
                token: token_sym.id,
                field: Field {
                    offset,
                    num_bits,
                    signed: field.signed,
                    hex: field.hex || (!field.dec),
                    attached: None
                },
            })?;
        }

        Ok(())
    }

    /// Handle a `attach variables` definition.
    ///
    /// Returns an error if any field in the field list has not been defined, or if any variable in
    /// the variable list cannot be resolved to a valid register.
    pub fn attach_variables(&mut self, attach: ast::AttachVariables) -> Result<(), String> {
        let mut mapping = Vec::with_capacity(attach.registers.len());
        let mut size = None;
        for register in attach.registers {
            if register == self.placeholder_ident {
                mapping.push(None);
                continue;
            }

            let id = self.lookup_kind(register, SymbolKind::Register)?;
            let new_size = self.registers[id as usize].size;

            // Ensure that all registers in the group are the same size
            if size.is_some() && size != Some(new_size) {
                return Err("attach register size mismatch".into());
            }

            size = Some(new_size);
            mapping.push(Some(id));
        }

        if size.is_none() {
            // There were no registers actually mapped as part of this attach statement.
            return Ok(());
        }
        self.define_attachment(Attachment::Register(mapping, size), &attach.fields)
    }

    /// Attach the alternative meaning `def` to the integers obtained when extracting the value of
    /// `fields`.
    ///
    /// Returns an error if any field in `fields` does not exist
    pub fn define_attachment(
        &mut self,
        def: Attachment,
        fields: &[ast::Ident],
    ) -> Result<(), String> {
        let attach_id = self.attachments.len().try_into().unwrap();
        self.attachments.push(def);
        for field in fields {
            self.add_attachment(*field, attach_id)?;
        }
        Ok(())
    }

    /// Attach `attachment_id` to the token or context field `ident`.
    ///
    /// Returns an error if `ident` does not correspond to a token or context field, or if the field
    /// has an existing attachment.
    fn add_attachment(&mut self, ident: ast::Ident, attachment_id: u32) -> Result<(), String> {
        let dst = match self.lookup(ident)? {
            Symbol { kind: SymbolKind::TokenField, id } => {
                &mut self.token_fields[id as usize].field
            }
            Symbol { kind: SymbolKind::ContextField, id } => {
                &mut self.context_fields[id as usize].field
            }
            _ => return Err("invalid symbol type for attachment".into()),
        };
        if dst.attached.replace(attachment_id).is_some() {
            return Err(format!("multiple attached meanings to: {}", ident.display(&self.parser)));
        }
        Ok(())
    }

    /// Handle a macro definition, returning an error if the identifier associated with the macro
    /// has already been defined.
    pub fn define_macro(&mut self, def: ast::Macro) -> Result<(), String> {
        insert_and_map!(self, macros, def.name, SymbolKind::Macro, Macro {
            name: def.name,
            params: def.params,
            body: def.body,
        })?;
        Ok(())
    }

    /// Handle a table definition, returning an error if the identifier associated with the table
    /// has already been defined.
    pub fn define_table(&mut self, name: ast::Ident) -> Result<(), String> {
        insert_and_map!(self, tables, name, SymbolKind::Table, Table {
            name,
            constructors: vec![],
            export: None,
        })?;
        Ok(())
    }

    /// Resolve a constructor, and add to its corresponding table
    ///
    /// Returns an error if the constructor is invalid.
    pub fn define_constructor(
        &mut self,
        ctx: &mut Context,
        constructor: &ast::Constructor,
    ) -> Result<(), String> {
        // Tables are declared implicitly, so create the table assocated with this constructor
        // if it does not exist
        let mut existing_table = true;
        if let Some(table) = constructor.table {
            existing_table = self.contains(table);
            if !existing_table {
                self.define_table(table).unwrap();
            }
        }

        let result = crate::constructor::build(ctx, self, constructor).map_err(|e| {
            format!(
                "{} Failed to build constructor: \"{}\": {}",
                self.format_span(&constructor.span),
                constructor.display(&self.parser),
                e
            )
        })?;

        let table = &mut self.tables[result.table as usize];

        let export_size = result.semantics.export.and_then(|value| value.size());
        if existing_table && table.export != export_size {
            return Err(format!(
                "Failed to add constructor \"{}\" to \"{}\": export size mismatch (existing: {:?}, new: {:?})",
                constructor.display(&self.parser),
                table.name.display(&self.parser),
                table.export,
                export_size
            ));
        }

        table.export = export_size;
        table.constructors.push(self.constructors.len().try_into().unwrap());

        self.constructors.push(result);

        Ok(())
    }

    pub fn format_span(&self, span: &ast::Span) -> String {
        match self.debug_info.get(&span.src) {
            Some(source) => source.format_span(span),
            None => format!("unknown({}):{}", span.src, span.start),
        }
    }

    pub fn format_constructor_line(&self, constructor: ConstructorId) -> String {
        let span = self.constructors[constructor as usize].span;
        match self.debug_info.get(&span.src) {
            Some(source) => source.format_span(&span),
            None => format!("unknown({}):{}", span.src, span.start),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RamSpace {
    /// The ID assigned to varnodes referencing this space
    pub space_id: pcode::MemId,

    /// Represents the number of bytes required to reference an arbitary address in the space (i.e.
    /// size_of::<*mut u8>()))
    pub size: ValueSize,

    /// Represents the size of a memory location associated with a single address
    pub word_size: ValueSize,
}

#[derive(Clone, Debug)]
pub(crate) struct Register {
    /// The name of the register
    pub name: ast::Ident,

    /// The offset of the register specified in the sleigh specification.
    pub offset: u32,

    /// The size of the register (in bytes).
    pub size: ValueSize,
}

#[derive(Clone, Debug)]
#[allow(unused)] // @todo: add full support for BitRanges
pub(crate) struct BitRange {
    /// The register this bitrange references
    pub register: RegisterId,

    /// Represents a contiguous range of bits within a bit stream in (lsb, msb) format
    pub range: ast::Range,
}

#[derive(Clone, Debug)]
pub(crate) struct Token {
    /// The endian, if this token overwride the global endian
    pub big_endian: Option<bool>,

    /// The number of bits in this token
    pub num_bits: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct TokenField {
    /// The token this field is associated with
    pub token: TokenId,

    /// Describes how to extract the value of the field
    pub field: Field,
}

#[derive(Clone, Debug)]
pub(crate) struct ContextField {
    /// The register this field is associated with.
    #[allow(unused)] // Currently we only support a single context register.
    pub register: RegisterId,

    /// The name of the field.
    pub name: ast::Ident,

    /// Describes how to extract the value of the field
    pub field: Field,

    /// Configures how `globalset` should be interpreted for this field. If `true`, `globalset`
    /// causes a permanent change to the processor state, if `false` the state will only be changed
    /// for the address referenced by the `globalset` directive.
    pub flow: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum Attachment {
    Register(Vec<Option<RegisterId>>, Option<ast::VarSize>),
    Name(Vec<String>),
    Value(Vec<i64>),
}

#[derive(Debug, Clone)]
pub(crate) struct Macro {
    /// The identifier associated with the macro
    pub name: ast::Ident,

    /// The name of each parameter in the macro's parameter list
    pub params: Vec<ast::Ident>,

    /// The body of the macro
    pub body: Vec<ast::Statement>,
}

#[derive(Debug, Clone)]
pub(crate) struct Table {
    /// The name of the table (equal to the string "instruction" for the root level table)
    pub name: ast::Ident,

    /// The constructors that can be used to build this table
    pub constructors: Vec<ConstructorId>,

    /// The size (in bytes) of the value exported by this table
    pub export: Option<ValueSize>,
}

#[derive(Debug, Clone)]
pub struct SourceFile {
    /// The name of the source file
    pub name: String,

    /// The offsets of each line in the source file.
    pub lines: Vec<u32>,
}

impl SourceFile {
    pub fn format_span(&self, span: &ast::Span) -> String {
        let line = self.lines.binary_search(&span.start).unwrap_or_else(|i| i.saturating_sub(1));
        let col = span.start - self.lines.get(line).unwrap_or(&0);
        format!("{}:{}:{}", self.name, line + 1, col)
    }
}

/// Converts a field range given in (`lsb`, `msb`) format to (`start`, `num_bits`).
fn field_range((lsb, msb): ast::Range) -> ast::Range {
    (lsb, (msb - lsb + 1))
}

/// Converts an inverted field range given in (`lsb`, `msb`) format to (`start`, `num_bits`).
///
/// The values of context fields are defined with a reversed bit order, so instead of reversing the
/// value each individual field, we reverse the entire source value, and invert the range.
///
/// e.g. Consider a 8-bit source, with a field `{ offset: 1, len: 2 }` will have the following
/// encoding:
///
/// ```text
/// 0 => xxxx_x00x
/// 1 => xxxx_x10x
/// 2 => xxxx_x01x
/// 3 => xxxx_x11x
/// ```
///
/// After reversing, we end up with the range `{ offset: 5, len: 2 }` with values:
///
/// ```text
/// 0 => x00x_xxxx
/// 1 => x01x_xxxx
/// 2 => x10x_xxxx
/// 3 => x11x_xxxx
/// ```
///
/// This can be be extracted with a simple shift and mask
fn inverted_field_range((lsb, msb): ast::Range, token_bits: u16) -> ast::Range {
    let (offset, num_bits) = field_range((lsb, msb));
    (token_bits - (offset + num_bits), num_bits)
}
