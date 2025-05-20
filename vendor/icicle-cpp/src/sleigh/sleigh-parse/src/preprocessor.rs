use std::collections::HashMap;

use crate::{
    ast::{self, ParserDisplay},
    lexer::{MacroKind, SourceId, TokenKind},
    parser::Parser,
    Error,
};

#[derive(Clone, Copy, Debug)]
enum BranchState {
    /// Current branch body is enabled
    Enabled,

    /// The current branch body is disabled because the expression was evaluated as false
    Disabled,

    /// The current branch body is disabled because a previous branch body was taken
    DisabledTaken,
}

impl BranchState {
    fn from_cond(cond: bool) -> Self {
        match cond {
            true => Self::Enabled,
            false => Self::Disabled,
        }
    }
}

#[derive(Default)]
pub struct State {
    /// Keeps track of all preprocessor definitions
    definitions: HashMap<ast::Ident, SourceId>,

    /// Keeps track of whether the current `@ifdef` statement is enabled or not
    enabled_stack: Vec<BranchState>,
}

impl State {
    /// Gets whether we are in a disabled section in the preprocessor
    pub fn is_disabled(&self) -> bool {
        !self.enabled_stack.last().map_or(true, |x| matches!(x, BranchState::Enabled))
    }

    /// Sets the current preprocessor branch state
    fn set_branch_state(&mut self, state: BranchState) {
        *self.enabled_stack.last_mut().unwrap() = state;
    }
}

/// Handle a preprocessor macro
pub(crate) fn handle_macro(p: &mut Parser, kind: MacroKind) -> Result<(), Error> {
    // If the preprocessor is in a disabled section, only look at a small subset of symbols
    if p.state.is_disabled() {
        match kind {
            MacroKind::If | MacroKind::IfDef | MacroKind::IfNotDef => {
                // This represents nested `@if` expression inside of a disabled branch, here we
                // need to update the stack, so `else` and `endif` statements match up correctly
                p.state.enabled_stack.push(BranchState::DisabledTaken);
            }

            MacroKind::Else | MacroKind::Elif => {
                if matches!(p.state.enabled_stack.last().unwrap(), BranchState::Disabled) {
                    // The if part of the expression was disabled, so else is enabled
                    p.state.set_branch_state(BranchState::Enabled);

                    if kind == MacroKind::Elif {
                        let state = parse_and_eval_if_expr(p)?;
                        p.state.set_branch_state(state);
                    }
                    else {
                        p.expect(TokenKind::Line)?;
                    }
                }
            }

            MacroKind::EndIf => {
                assert!(p.state.enabled_stack.pop().is_some(), "ICE: invalid preprocessor state");
            }

            // All other macros are ignored in disabled sections
            _ => {}
        }

        return Ok(());
    }

    match kind {
        MacroKind::If => {
            let state = parse_and_eval_if_expr(p)?;
            p.state.enabled_stack.push(state);
        }
        MacroKind::IfDef => {
            let ident = p.parse()?;
            p.expect(TokenKind::Line)?;
            let state = BranchState::from_cond(p.state.definitions.contains_key(&ident));
            p.state.enabled_stack.push(state);
        }
        MacroKind::IfNotDef => {
            let ident = p.parse()?;
            p.expect(TokenKind::Line)?;
            let state = BranchState::from_cond(!p.state.definitions.contains_key(&ident));
            p.state.enabled_stack.push(state);
        }

        MacroKind::Else | MacroKind::Elif => {
            // If reached an else statement when we were already in the enabled state, it must
            // mean that a previous if (or elif) expression was true so we should be disabled
            // at this point
            match p.state.enabled_stack.last_mut() {
                Some(entry) => *entry = BranchState::DisabledTaken,
                None => return Err(p.error("unexpected `@else` expression")),
            }
        }
        MacroKind::EndIf => {
            if p.state.enabled_stack.pop().is_none() {
                return Err(p.error("unexpected `@endif` expression"));
            }
            p.expect(TokenKind::Line)?;
        }

        MacroKind::Include => {
            let file_name = p.parse_string()?;
            p.expect(TokenKind::Line)?;
            p.include_file(file_name)?;
        }
        MacroKind::Define => {
            let ident = p.parse()?;

            let token = p.peek();
            let value = match token.kind {
                TokenKind::String => p.parse_string()?,
                TokenKind::Number => {
                    let token = p.next();
                    p.get_str(token).into()
                }
                TokenKind::Line => "".into(),
                _ => return Err(token.error_unexpected(&[TokenKind::String, TokenKind::Number])),
            };
            p.expect(TokenKind::Line)?;
            define(p, ident, value);
        }
        MacroKind::Undef => {
            let ident = p.parse()?;
            p.expect(TokenKind::Line)?;
            p.state.definitions.remove(&ident);
        }
        MacroKind::Expand => {
            p.expect(TokenKind::LeftParen)?;
            let ident = p.parse()?;
            p.expect(TokenKind::RightParen)?;

            let src = lookup(p, ident)?;
            p.expand_here(src)?;
        }

        MacroKind::Unknown => return Err(p.error("Unknown macro")),
    }

    Ok(())
}

/// Adds a definition specifying that the preprocessor symbol `name` should be mapped to
/// `content`
///
/// Note: preprocessor symbols are allowed to be redefined
pub(crate) fn define(p: &mut Parser, ident: ast::Ident, content: impl Into<String>) {
    let name = format!("$({})", p.interner.get(ident.0));
    let src_id = p.load_content(name, content.into());
    p.state.definitions.insert(ident, src_id);
}

/// Looks up a symbol in the preprocessor definition table, returning an error if the symbol is
/// has yet to be defined
fn lookup(p: &Parser, ident: ast::Ident) -> Result<SourceId, Error> {
    Ok(*p
        .state
        .definitions
        .get(&ident)
        .ok_or_else(|| p.error(format!("symbol `{}` is undefined", ident.display(p))))?)
}

fn resolve_macro_symbol<'a>(p: &'a Parser, symbol: &'a MacroSymbol) -> Result<&'a str, Error> {
    Ok(match symbol {
        MacroSymbol::Ident(ident) => &p.sources[lookup(p, *ident)? as usize].content,
        MacroSymbol::String(value) => value,
    })
}

#[derive(Debug, Clone)]
enum MacroExpr {
    Defined(ast::Ident),
    Equal(MacroSymbol, MacroSymbol),
    NotEqual(MacroSymbol, MacroSymbol),
    Op(Box<MacroExpr>, MacroOp, Box<MacroExpr>),
}

#[derive(Debug, Clone)]
enum MacroSymbol {
    Ident(ast::Ident),
    String(String),
}

#[derive(Debug, Clone)]
enum MacroOp {
    And,
    Or,
    Xor,
}

fn parse_and_eval_if_expr(p: &mut Parser) -> Result<BranchState, Error> {
    let expr = parse_macro_expr(p)?;
    p.expect(TokenKind::Line)?;
    Ok(BranchState::from_cond(eval_macro_expr(p, &expr)?))
}

fn eval_macro_expr(p: &mut Parser, expr: &MacroExpr) -> Result<bool, Error> {
    let cmp = |a: &MacroSymbol, b: &MacroSymbol| -> Result<bool, Error> {
        let a = resolve_macro_symbol(p, a)?;
        let b = resolve_macro_symbol(p, b)?;
        Ok(a == b)
    };

    Ok(match expr {
        MacroExpr::Defined(sym) => p.state.definitions.contains_key(sym),
        MacroExpr::Equal(a, b) => cmp(a, b)?,
        MacroExpr::NotEqual(a, b) => !cmp(a, b)?,
        MacroExpr::Op(lhs, MacroOp::And, rhs) => {
            eval_macro_expr(p, lhs)? && eval_macro_expr(p, rhs)?
        }
        MacroExpr::Op(lhs, MacroOp::Or, rhs) => {
            eval_macro_expr(p, lhs)? || eval_macro_expr(p, rhs)?
        }
        MacroExpr::Op(lhs, MacroOp::Xor, rhs) => {
            eval_macro_expr(p, lhs)? ^ eval_macro_expr(p, rhs)?
        }
    })
}

/// Parses a preprocessor expression
fn parse_macro_expr(p: &mut Parser) -> Result<MacroExpr, Error> {
    const EXPECTED_TOKENS: &[TokenKind] =
        &[TokenKind::String, TokenKind::Ident, TokenKind::Defined, TokenKind::LeftParen];

    let token = p.peek();
    let result = match token.kind {
        TokenKind::Defined => {
            let _ = p.next();
            p.expect(TokenKind::LeftParen)?;
            let ident = p.parse()?;
            p.expect(TokenKind::RightParen)?;
            MacroExpr::Defined(ident)
        }
        TokenKind::LeftParen => {
            let _ = p.next();
            let inner = parse_macro_expr(p)?;
            p.expect(TokenKind::RightParen)?;
            inner
        }
        TokenKind::Ident | TokenKind::String => {
            let lhs = parse_macro_symbol(p).unwrap();
            parse_macro_expr_rhs(p, lhs)?
        }
        _ => return Err(token.error_unexpected(EXPECTED_TOKENS)),
    };

    let token = p.peek();
    match token.kind {
        TokenKind::Hat => {
            p.expect(TokenKind::Hat)?;
            p.expect(TokenKind::Hat)?;
            Ok(MacroExpr::Op(Box::new(result), MacroOp::Xor, Box::new(parse_macro_expr(p)?)))
        }
        TokenKind::Bar => {
            p.expect(TokenKind::Bar)?;
            p.expect(TokenKind::Bar)?;
            Ok(MacroExpr::Op(Box::new(result), MacroOp::Or, Box::new(parse_macro_expr(p)?)))
        }
        TokenKind::Ampersand => {
            p.expect(TokenKind::Ampersand)?;
            p.expect(TokenKind::Ampersand)?;
            Ok(MacroExpr::Op(Box::new(result), MacroOp::And, Box::new(parse_macro_expr(p)?)))
        }
        TokenKind::RightParen | TokenKind::Line => Ok(result),

        _ => {
            use TokenKind::*;
            Err(token.error_unexpected(&[Hat, Bar, Ampersand, RightParen, Line]))
        }
    }
}

fn parse_macro_symbol(p: &mut Parser) -> Result<MacroSymbol, Error> {
    let token = p.peek();
    match token.kind {
        TokenKind::Ident => Ok(MacroSymbol::Ident(p.parse::<ast::Ident>()?)),
        TokenKind::String => Ok(MacroSymbol::String(p.parse_string()?)),
        _ => Err(token.error_unexpected(&[TokenKind::Ident, TokenKind::String])),
    }
}

fn parse_macro_expr_rhs(p: &mut Parser, lhs: MacroSymbol) -> Result<MacroExpr, Error> {
    let token = p.next();
    match token.kind {
        TokenKind::ExclamationMark => {
            p.expect(TokenKind::Equal)?;
            Ok(MacroExpr::NotEqual(lhs, parse_macro_symbol(p)?))
        }
        TokenKind::Equal => {
            p.expect(TokenKind::Equal)?;
            Ok(MacroExpr::Equal(lhs, parse_macro_symbol(p)?))
        }
        _ => Err(token.error_unexpected(&[TokenKind::Equal, TokenKind::ExclamationMark])),
    }
}
