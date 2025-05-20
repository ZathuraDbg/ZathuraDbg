use sleigh_parse::ast;
use sleigh_runtime::{semantics::Local, DisplaySegment};

use crate::{constructor::Scope, symbols::SymbolKind, Context};

pub(crate) fn resolve(
    ctx: &mut Context,
    scope: &Scope,
    constructor: &ast::Constructor,
) -> Result<(u32, u32), String> {
    let mut display = vec![];
    if let Some(mnemonic) = &constructor.mnemonic {
        display.push(DisplaySegment::Literal(ctx.add_string(mnemonic)));
    }

    for entry in &constructor.display {
        display.push(resolve_segment(ctx, scope, entry)?);
    }

    Ok(ctx.cache.add_display_segment(&display, &mut ctx.data))
}

fn resolve_segment(
    ctx: &mut Context,
    scope: &Scope,
    entry: &ast::DisplaySegment,
) -> Result<DisplaySegment, String> {
    Ok(match entry {
        ast::DisplaySegment::Ident(ident) => match scope.lookup(*ident) {
            Some(Local::Field(field)) => DisplaySegment::Field(field),
            Some(Local::Subtable(index)) => DisplaySegment::Subtable(index),
            _ => {
                // Registers in the display segment are just treated as literals
                let _ = scope
                    .globals
                    .lookup_kind(*ident, SymbolKind::Register)
                    .map_err(|e| format!("Error resolving segment: {e}"))?;
                DisplaySegment::Literal(ctx.add_string(scope.globals.parser.get_ident_str(*ident)))
            }
        },
        ast::DisplaySegment::Literal(value) => DisplaySegment::Literal(ctx.add_string(value)),
    })
}
