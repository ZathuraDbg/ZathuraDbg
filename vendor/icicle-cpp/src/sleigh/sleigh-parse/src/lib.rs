pub mod ast;

mod error;
mod input;
mod lexer;
mod parser;
mod preprocessor;

#[cfg(test)]
mod tests;

pub use crate::{
    error::*,
    input::{FileLoader, Input},
    parser::Parser,
};

use std::collections::HashMap;

/// Resolve all the content and names of all the files referenced by the sleigh spec starting at
/// `path`. This can be used to embed the input of a sleigh specification into a binary.
///
/// # Errors
///
/// Returns an error if there was an error parsing the sleigh specification.
pub fn resolve_dependencies(
    path: impl AsRef<std::path::Path>,
) -> Result<HashMap<String, String>, String> {
    let mut parser = Parser::from_path(path)?;
    if let Err(e) = parser.parse::<ast::Sleigh>() {
        return Err(format!("{}", parser.error_formatter(e)));
    }
    Ok(parser.sources.into_iter().map(|input| (input.name, input.content)).collect())
}
