use std::collections::HashMap;

use sleigh_parse::ast;
use sleigh_runtime::{
    matcher::{Constraint, ConstraintOperand},
    DecodeAction, EvalKind, Field, Token,
};

use crate::{
    constructor::{resolve_pattern_expr, ResolveIdent, Scope},
    symbols::{SymbolKind, TokenFieldId},
};

/// Resolves the constraint expression `expr` into one or more simplified constraint lists.
///
/// Any fields specified as part of the constraint expression will be added to `scope`
pub(crate) fn resolve(
    scope: &mut Scope,
    expr: &ast::ConstraintExpr,
) -> Result<(Vec<Vec<Constraint>>, Vec<DecodeAction>), String> {
    ConstraintVisitor::new(scope, expr).resolve_root()
}

#[derive(Clone, Copy, Debug)]
enum Direction {
    Left,
    Right,
}

#[derive(Copy, Clone)]
enum OperandSource {
    Token,
    Context,
}

/// A visitor for resolving a constraint expression into one or more simplified constraint lists and
/// list of fields
struct ConstraintVisitor<'a, 'b> {
    scope: &'a mut Scope<'b>,
    root: &'a ast::ConstraintExpr,

    /// Each entry represents a finalized set of constraints that if satisfied means the
    /// constructor matches.
    lists: Vec<Vec<Constraint>>,

    /// The set of actions to perform during the disassembly process.
    actions: Vec<DecodeAction>,

    /// Keeps track of which edges in the AST have been taken.
    fork_directions: HashMap<usize, Direction>,

    /// The partial constraint expression for the current fork.
    current_constraints: Vec<Constraint>,

    /// The current token offset (in bits).
    offset: usize,

    /// The number of bits in the largest token seen at the current offset.
    bits: u8,

    /// The ID of the current node in the constraint expression AST, used for keeping track of
    /// which parts of the tree have been evaluated.
    node: usize,
}

impl<'a, 'b> ConstraintVisitor<'a, 'b> {
    fn new(scope: &'a mut Scope<'b>, root: &'a ast::ConstraintExpr) -> Self {
        Self {
            scope,
            root,
            fork_directions: HashMap::new(),
            lists: vec![],
            current_constraints: vec![],
            actions: vec![],
            offset: 0,
            bits: 0,
            node: 0,
        }
    }

    /// Resolve the constraint tree from the root node, returning a tuple consisting of: (all valid
    /// constraint lists, actions to perform during decoding)
    fn resolve_root(mut self) -> Result<(Vec<Vec<Constraint>>, Vec<DecodeAction>), String> {
        self.resolve(self.root)?;
        self.lists.push(self.current_constraints);
        Ok((self.lists, self.actions))
    }

    fn resolve_root_with(&mut self, directions: HashMap<usize, Direction>) -> Result<(), String> {
        let mut fork = ConstraintVisitor::new(self.scope, self.root);
        fork.fork_directions = directions;

        // @fixme: check that each fork performs the same actions
        let (constraints, _actions) = fork.resolve_root()?;
        self.lists.extend(constraints);
        Ok(())
    }

    fn operand_expr(
        &self,
        expr: &ast::PatternExpr,
        src: OperandSource,
    ) -> Result<ConstraintOperand, String> {
        match expr {
            ast::PatternExpr::Ident(ident) => {
                let field = match src {
                    OperandSource::Token => TokenResolver::resolve_ident(self.scope, *ident)?,
                    OperandSource::Context => ContextResolver::resolve_ident(self.scope, *ident)?,
                };
                Ok(ConstraintOperand::Field(field))
            }
            ast::PatternExpr::Integer(x) => Ok(ConstraintOperand::Constant(*x as i64)),

            _ => {
                let mut out = vec![];
                match src {
                    OperandSource::Token => {
                        resolve_pattern_expr::<TokenResolver>(&self.scope, expr, &mut out)?
                    }
                    OperandSource::Context => {
                        resolve_pattern_expr::<ContextResolver>(&self.scope, expr, &mut out)?
                    }
                };
                Ok(ConstraintOperand::Expr(out))
            }
        }
    }

    fn update_token_size(&mut self, field_id: TokenFieldId) {
        let token = self.scope.globals.token_fields[field_id as usize].token;
        let new = self.scope.globals.tokens[token as usize].num_bits;
        if self.bits == 0 {
            self.bits = new;
            self.actions.push(DecodeAction::NextToken(new / 8))
        }
        else if self.bits != new {
            panic!("incompatible token expected size = {}, got size = {}", self.bits, new);
        }
    }

    fn add_action(&mut self, action: DecodeAction) {
        match (self.actions.last(), &action) {
            (Some(DecodeAction::GroupStart), DecodeAction::GroupEnd)
            | (Some(DecodeAction::ExpandStart), DecodeAction::ExpandEnd) => {
                self.actions.pop();
            }
            _ => self.actions.push(action),
        }
    }

    fn resolve(&mut self, expr: &ast::ConstraintExpr) -> Result<(), String> {
        self.node += 1;
        match expr {
            &ast::ConstraintExpr::Ident(ident) => {
                // A predefined symbol representing "no constraint"
                if ident == self.scope.globals.epsilon_ident {
                    return Ok(());
                }

                let symbol = self.scope.globals.lookup(ident)?;
                match symbol.kind {
                    SymbolKind::ContextField => {
                        let field = self.scope.globals.context_fields[symbol.id as usize].field;
                        let index = self.scope.add_field(ident, field)?;
                        self.add_action(DecodeAction::Eval(index, EvalKind::ContextField(field)));
                    }

                    SymbolKind::TokenField => {
                        self.update_token_size(symbol.id);

                        let (token, field) = self.resolve_token_field(symbol);
                        let index = self.scope.add_field(ident, field)?;
                        self.scope.tokens.insert(index, token.offset(self.offset as u8 / 8));
                        self.add_action(DecodeAction::Eval(
                            index,
                            EvalKind::TokenField(token, field),
                        ));
                    }

                    SymbolKind::Table => {
                        let index = self.scope.add_subtable(ident, symbol.id)?;
                        self.add_action(DecodeAction::Subtable(index, symbol.id));
                    }

                    // Registers can appear in a bare identifier in a constraint expression,
                    // allowing them to be referenced in the display section. However it is no
                    // different to them being used implicitly.
                    SymbolKind::Register => {}

                    _ => {
                        return Err(format!(
                            "invalid pattern field: {:?}<{}>",
                            symbol.kind,
                            self.scope.debug(&ident)
                        ));
                    }
                }
            }
            ast::ConstraintExpr::Cmp(ident, op, value) => {
                let symbol = self.scope.globals.lookup(*ident)?;
                match symbol.kind {
                    SymbolKind::TokenField => {
                        self.update_token_size(symbol.id);
                        let (token, field) = self.resolve_token_field(symbol);
                        let operand = self.operand_expr(value, OperandSource::Token)?;
                        self.current_constraints.push(Constraint::Token {
                            token: token.offset(self.offset as u8 / 8),
                            field,
                            cmp: *op,
                            operand,
                        })
                    }
                    SymbolKind::ContextField => {
                        let field = self.scope.globals.context_fields[symbol.id as usize].field;
                        let operand = self.operand_expr(value, OperandSource::Context)?;
                        self.current_constraints.push(Constraint::Context {
                            field,
                            cmp: *op,
                            operand,
                        });
                    }
                    _ => {
                        return Err(format!(
                            "expected valid constraint symbol: {}",
                            self.scope.debug(ident)
                        ));
                    }
                }
            }
            ast::ConstraintExpr::Op(lhs, ast::ConstraintOp::And, rhs) => {
                self.resolve(lhs)?;
                self.resolve(rhs)?;
            }
            ast::ConstraintExpr::Op(lhs, ast::ConstraintOp::Concat, rhs) => {
                let offset = self.offset;
                let bits = self.bits;

                self.resolve(lhs)?;

                self.offset += self.bits as usize;
                self.bits = 0;
                self.add_action(DecodeAction::GroupStart);

                self.resolve(rhs)?;

                self.add_action(DecodeAction::GroupEnd);
                self.offset = offset;
                self.bits = bits;
            }
            ast::ConstraintExpr::Op(lhs, ast::ConstraintOp::Or, rhs) => {
                let current_node = self.node;
                match self.fork_directions.get(&current_node) {
                    Some(Direction::Right) => self.resolve(rhs)?,
                    Some(Direction::Left) => self.resolve(lhs)?,
                    None => {
                        let mut rhs_directions = self.fork_directions.clone();

                        // Assume RHS is false and resolve LHS
                        self.fork_directions.insert(current_node, Direction::Left);
                        self.resolve(lhs)?;

                        // Assume LHS is false and resolve RHS
                        rhs_directions.insert(current_node, Direction::Right);
                        self.resolve_root_with(rhs_directions)?;
                    }
                }
            }
            ast::ConstraintExpr::ExtendLeft(inner) => {
                self.add_action(DecodeAction::ExpandStart);
                self.resolve(inner)?;
                self.add_action(DecodeAction::ExpandEnd);
            }
            ast::ConstraintExpr::ExtendRight(inner) => {
                self.add_action(DecodeAction::ExpandStart);
                self.resolve(inner)?;
                self.add_action(DecodeAction::ExpandEnd);
            }
        }

        Ok(())
    }

    fn resolve_token_field(&mut self, sym: crate::symbols::Symbol) -> (Token, Field) {
        let field = &self.scope.globals.token_fields[sym.id as usize];
        let token = &self.scope.globals.tokens[field.token as usize];
        let token = Token::new(
            token.num_bits / 8,
            token.big_endian.unwrap_or(self.scope.globals.endianness == ast::EndianKind::Big),
        );
        (token, field.field)
    }
}

struct TokenResolver;

impl ResolveIdent for TokenResolver {
    type Output = Field;

    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self::Output, String> {
        let id = scope.globals.lookup_kind(ident, SymbolKind::TokenField)?;
        Ok(scope.globals.token_fields[id as usize].field)
    }
}

struct ContextResolver;

impl ResolveIdent for ContextResolver {
    type Output = Field;

    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self::Output, String> {
        let id = scope.globals.lookup_kind(ident, SymbolKind::ContextField)?;
        Ok(scope.globals.context_fields[id as usize].field)
    }
}
