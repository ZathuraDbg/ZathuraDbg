use std::collections::HashMap;

use sleigh_parse::ast;
use sleigh_runtime::{
    matcher::Constraint,
    semantics::{Local, PcodeTmp, SemanticAction, ValueSize},
    DecodeAction, Field, PatternExprOp, Token,
};

use crate::{
    symbols::{Attachment, SymbolKind, SymbolTable, TableId},
    Context,
};

pub use self::semantics::Semantics;

mod display;

mod constraints;
mod disasm_actions;
mod semantics;

#[derive(Clone)]
pub(crate) struct Constructor {
    /// The table associated with this constructor
    pub table: TableId,

    /// The mnemonic associated with the constructor
    pub mnemonic: Option<String>,

    /// The display section encoding
    pub display: (u32, u32),

    /// Fields declared during a constraint or disassembly action section
    pub fields: Vec<Field>,

    /// Subtables referenced by this constructor
    pub subtables: Vec<TableId>,

    /// Actions to perform as part of the constraint expression
    pub decode_actions: Vec<DecodeAction>,

    /// One (or more) constraint lists that need to be satisfied to match the constructor
    ///
    /// (Multiple constraint lists are generated as a result of OR expressions)
    pub constraints: Vec<Vec<Constraint>>,

    /// Modifications to the processor context that performed during the disassembly process
    pub disasm_actions: disasm_actions::DisasmActions,

    /// Operations to perform as part of the semantics section
    pub semantics: Semantics,

    /// Keeps track of where the constructor was defined in the source file.
    pub span: ast::Span,
}

impl Constructor {
    #[allow(unused)] // @todo: We can use this as an optimization during constructor matching.
    pub fn is_prefix(&self) -> bool {
        self.semantics.actions.is_empty()
            && self.disasm_actions.fields.is_empty()
            && self.subtables.contains(&self.table)
    }

    pub fn has_delay_slot(&self) -> bool {
        self.semantics.actions.iter().any(|x| matches!(x, SemanticAction::DelaySlot))
    }
}

pub(crate) fn build(
    ctx: &mut Context,
    symbols: &SymbolTable,
    constructor: &ast::Constructor,
) -> Result<Constructor, String> {
    // Constructors without a table name belong to the root level table which is assigned the
    // special "instruction" keyword.
    let table_ident = constructor.table.unwrap_or(symbols.root_table_ident);
    let table = symbols.lookup_kind(table_ident, SymbolKind::Table)?;
    let mut scope = Scope::new(symbols);

    let (constraints, decode_actions) = constraints::resolve(&mut scope, &constructor.constraint)?;

    let disasm_actions = disasm_actions::resolve(&mut scope, &constructor.disasm_actions)?;
    let mut semantics = semantics::resolve(&mut scope, &constructor.semantics)?;
    semantics.temporaries = scope.temporaries.clone();

    Ok(Constructor {
        table,
        mnemonic: constructor.mnemonic.clone(),
        display: display::resolve(ctx, &scope, constructor)?,
        subtables: scope.subtables,
        fields: scope.fields,
        decode_actions,
        constraints,
        disasm_actions,
        semantics,
        span: constructor.span,
    })
}

pub(crate) type FieldIndex = u32;

#[derive(Debug, Copy, Clone)]
pub(crate) struct PcodeLabel {
    /// The ID associated with this label
    pub id: u16,

    /// Defines whether the label has been defined yet. If false, the label has only been seen as
    /// destination of a goto
    pub defined: bool,

    /// Whether this label is ever referenced with a back edge
    pub back_edge: bool,
}

pub(crate) struct Scope<'a> {
    /// The local fields defined in either the constraint expression or as part of disassembly
    /// actions.
    pub fields: Vec<Field>,

    /// The subtables referenced by this constructor.
    pub subtables: Vec<TableId>,

    /// A reference to the global symbol table.
    globals: &'a SymbolTable,

    /// Keeps track of the sizes of temporaries assigned as part of the semantic section.
    temporaries: Vec<PcodeTmp>,

    /// A mapping from a field index to a token. This mapping is only used for handling token field
    /// evaluations that takes place during expressions that modify the context field.
    tokens: HashMap<u32, Token>,

    /// Keeps track of the mapping between identifiers and locals defined in the current scope.
    mapping: HashMap<ast::Ident, Local>,

    /// Keeps track of the mapping between labels and their IDs
    labels: HashMap<ast::Ident, PcodeLabel>,
}

impl<'a> Scope<'a> {
    pub fn new(globals: &'a SymbolTable) -> Self {
        Self {
            globals,
            fields: vec![],
            subtables: vec![],
            temporaries: vec![],
            tokens: HashMap::new(),
            mapping: HashMap::new(),
            labels: HashMap::new(),
        }
    }

    /// Resolve the symbol associated with `key` in the current scope
    pub fn lookup(&self, key: ast::Ident) -> Option<Local> {
        match key {
            key if key == self.globals.inst_next_ident => Some(Local::InstNext),
            key if key == self.globals.inst_start_ident => Some(Local::InstStart),
            _ => Some(*self.mapping.get(&key)?),
        }
    }

    pub fn declare_local(
        &mut self,
        name: ast::Ident,
        local: impl Into<Local>,
    ) -> Result<Local, String> {
        let local = local.into();
        if self.mapping.insert(name, local).is_some() {
            return Err(format!("redeclaration of variable: {}", self.debug(&name)));
        }
        Ok(local)
    }

    pub fn add_field(&mut self, ident: ast::Ident, field: Field) -> Result<FieldIndex, String> {
        match self.lookup(ident) {
            Some(Local::Field(index)) => Ok(index),
            Some(other) => Err(format!("invalid field: {:?}<{}>", other, self.debug(&ident))),
            None => {
                let index = self.fields.len().try_into().unwrap();
                self.fields.push(field);
                self.declare_local(ident, Local::Field(index))?;
                Ok(index)
            }
        }
    }

    pub fn add_subtable(&mut self, ident: ast::Ident, table: TableId) -> Result<u32, String> {
        match self.lookup(ident) {
            Some(Local::Subtable(index)) => Ok(index),
            Some(other) => Err(format!("invalid subtable: {:?}<{}>", other, self.debug(&ident))),
            None => {
                let index = self.subtables.len().try_into().unwrap();
                self.subtables.push(table);
                self.declare_local(ident, Local::Subtable(index))?;
                Ok(index)
            }
        }
    }

    pub fn add_tmp(&mut self, size: Option<ValueSize>) -> Local {
        let id = self.temporaries.len().try_into().unwrap();
        self.temporaries.push(PcodeTmp { name: None, size });
        Local::PcodeTmp(id)
    }

    pub fn named_tmp(
        &mut self,
        ident: ast::Ident,
        size: Option<ValueSize>,
    ) -> Result<Local, String> {
        let local = Local::PcodeTmp(self.temporaries.len().try_into().unwrap());
        self.temporaries.push(PcodeTmp { name: Some(ident), size });
        self.declare_local(ident, local)?;
        Ok(local)
    }

    pub fn size_of(&self, local: Local) -> Option<ValueSize> {
        match local {
            Local::Register(id) => Some(self.globals.registers[id as usize].size),
            Local::Subtable(index) | Local::SubtableRef(index) => {
                self.globals.tables[self.subtables[index as usize] as usize].export
            }
            Local::Field(idx) => {
                let field = &self.fields[idx as usize];
                match field.attached.map(|attach| &self.globals.attachments[attach as usize]) {
                    Some(Attachment::Register(_, size)) => *size,
                    Some(Attachment::Value(_)) => None,
                    _ => None,
                }
            }
            Local::PcodeTmp(id) => self.temporaries[id as usize].size,
            Local::Constant(_) => None,
            Local::InstNext | Local::InstStart => None,
        }
    }

    pub fn get_or_insert_label(&mut self, name: &ast::Ident) -> &mut PcodeLabel {
        let next_label: u16 = self.labels.len().try_into().unwrap();
        self.labels.entry(name.to_owned()).or_insert_with(|| PcodeLabel {
            id: next_label,
            defined: false,
            back_edge: false,
        })
    }

    pub fn debug<'b, T: ast::ParserDisplay>(
        &self,
        item: &'b T,
    ) -> ast::ParserDisplayWrapper<'b, 'a, T> {
        item.display(&self.globals.parser)
    }
}

pub(crate) trait ResolveIdent: Sized {
    type Output;
    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self::Output, String>;
}

pub(crate) fn resolve_pattern_expr<R>(
    scope: &Scope,
    expr: &ast::PatternExpr,
    out: &mut Vec<PatternExprOp<R::Output>>,
) -> Result<(), String>
where
    R: ResolveIdent,
{
    let op = match expr {
        ast::PatternExpr::Ident(ident) => PatternExprOp::Value(R::resolve_ident(scope, *ident)?),
        ast::PatternExpr::Integer(value) => PatternExprOp::Constant(*value),
        ast::PatternExpr::Op(a, op, b) => {
            resolve_pattern_expr::<R>(scope, a, out)?;
            resolve_pattern_expr::<R>(scope, b, out)?;
            PatternExprOp::Op(*op)
        }
        ast::PatternExpr::Not(inner) => {
            resolve_pattern_expr::<R>(scope, inner, out)?;
            PatternExprOp::Not
        }
        ast::PatternExpr::Negate(inner) => {
            resolve_pattern_expr::<R>(scope, inner, out)?;
            PatternExprOp::Negate
        }
    };
    out.push(op);
    Ok(())
}
