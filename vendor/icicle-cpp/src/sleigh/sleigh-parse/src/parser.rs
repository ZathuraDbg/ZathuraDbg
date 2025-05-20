use std::collections::{HashMap, VecDeque};

use crate::{
    ast::{self, ExprTable, VarSize},
    input::Input,
    lexer::{self, Lexer, SourceId, Token, TokenKind},
    preprocessor, Error, ErrorExt, Span,
};

/// Limits the maximum macro expansion depth (used to detect cycles).
const MAX_EXPANSION_DEPTH: usize = 16;

pub struct LoadedSource {
    /// The name import name of the file or macro definition.
    pub name: String,

    /// The raw contents of the source.
    pub content: String,

    /// The character offset of every line in the file.
    pub lines: Vec<u32>,
}

impl LoadedSource {
    /// Convert a character offset to a (line, column) offset
    ///
    /// Note: line and column are both 0 indexed
    pub fn line_and_column(&self, char_offset: u32) -> (usize, usize) {
        let line = self.lines.binary_search(&char_offset).unwrap_or_else(|i| i.saturating_sub(1));
        let col = char_offset - self.lines.get(line).unwrap_or(&0);
        (line, col as usize)
    }
}

pub type StrIndex = (u32, u32);

#[derive(Default)]
pub struct Interner {
    strings: String,
    index: HashMap<String, (u32, u32)>,
}

impl Interner {
    pub fn intern(&mut self, s: &str) -> StrIndex {
        if let Some(&index) = self.index.get(s) {
            return index;
        }

        let start = self.strings.len() as u32;
        self.strings.push_str(s);
        let end = self.strings.len() as u32;
        self.index.insert(s.to_string(), (start, end));

        (start, end)
    }

    pub fn lookup(&self, s: &str) -> Option<StrIndex> {
        self.index.get(s).copied()
    }

    pub fn get(&self, index: StrIndex) -> &str {
        &self.strings[index.0 as usize..index.1 as usize]
    }
}

pub struct Parser {
    /// The input source
    input: Box<dyn Input>,

    /// A lexer for each level of preprocessor expansion.
    lexers: Vec<Lexer>,

    /// Tokens that have been peeked from the token stream, but have yet to be consumed
    peeked: VecDeque<Token>,

    /// Controls whether we are currently parsing a display section (which changes the lexer mode).
    lexer_mode: lexer::Mode,

    /// Configures which tokens should be skipped when calling `next_token`, this is generally used
    /// to ignore whitespace and comments
    ignored_tokens: &'static [TokenKind],

    /// The last error seen by the parser.
    pub error: Option<Error>,

    /// Expressions that we have parsed so far.
    pub exprs: ExprTable,

    /// The contents of each source loaded so far
    pub sources: Vec<LoadedSource>,

    /// The state associated with the preprocessor
    pub state: preprocessor::State,

    /// Storage for interned strings.
    pub interner: Interner,
}

impl Parser {
    fn new<I: Input + 'static>(input: I, defines: &[impl AsRef<str>]) -> Self {
        let mut parser = Self {
            input: Box::new(input),
            sources: vec![],
            exprs: ExprTable::default(),
            lexers: Vec::new(),
            lexer_mode: lexer::Mode::Normal,
            peeked: VecDeque::new(),
            ignored_tokens: &[TokenKind::Comment, TokenKind::Whitespace, TokenKind::Line],
            state: preprocessor::State::default(),
            error: None,
            interner: Interner::default(),
        };

        for define in defines {
            let icicle_ident = ast::Ident(parser.interner.intern(define.as_ref()));
            preprocessor::define(&mut parser, icicle_ident, "");
        }

        parser
    }

    pub fn from_str(content: &str) -> Self {
        let mut input_source = HashMap::default();
        input_source.insert("input".into(), content.into());

        let mut preprocessor = Parser::new(input_source, &["ICICLE"]);
        preprocessor.include_file("input").unwrap();

        preprocessor
    }

    pub fn from_input<I: Input + 'static>(root: &str, input: I) -> Result<Self, String> {
        // `ifdef ICICLE` is used in our patched specifications for Icicle specific changes.
        let mut parser = Self::new(input, &["ICICLE"]);
        match parser.include_file(root) {
            Ok(_) => Ok(parser),
            Err(e) => Err(format!("{}", parser.error_formatter(e))),
        }
    }

    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let path = path.as_ref();

        let root = path.parent().ok_or("Invalid input path")?;
        let input_source = crate::input::FileLoader::new(root.to_owned());

        let initial_file = path.file_name().and_then(|x| x.to_str()).ok_or("Invalid input path")?;
        Self::from_input(initial_file, input_source)
    }

    /// Gets or creates a new [ast::Ident] in the interner from the given string.
    pub fn get_ident(&mut self, s: &str) -> ast::Ident {
        let index = self.interner.intern(s);
        ast::Ident(index)
    }

    /// Gets the string slice associated with `ident`.
    pub fn get_ident_str(&self, ident: ast::Ident) -> &str {
        self.interner.get(ident.0)
    }

    /// Creates a wrapper that is used for formatting an error message
    pub fn error_formatter(&self, error: Error) -> ErrorFormatter {
        ErrorFormatter { inner: self, error }
    }

    /// Gets the string slice associated with `token`
    pub(crate) fn get_str(&self, token: Token) -> &str {
        let src = &self.sources[token.span.src as usize];
        &src.content[token.span.range()]
    }

    /// Gets the string slice associated with `token` and interns it.
    pub(crate) fn intern_token(&mut self, token: Token) -> StrIndex {
        let src = &self.sources[token.span.src as usize];
        self.interner.intern(&src.content[token.span.range()])
    }

    /// Get a span representing the current position
    pub(crate) fn current_span(&self) -> Span {
        self.lexers.last().map_or(Span::none(), |lex| lex.current_span())
    }

    /// Create a new error message at the current location
    pub(crate) fn error(&self, msg: impl Into<String>) -> Error {
        Error {
            message: msg.into(),
            span: self.current_span(),
            cause: self.error.as_ref().map(|err| Box::new(err.clone())),
        }
    }

    /// Create an error corresponding to
    pub(crate) fn error_unexpected(&mut self, token: Token, expected: &[TokenKind]) -> Error {
        if token.kind == TokenKind::ParseError {
            if let Some(prev) = self.error.take() {
                return prev;
            }
        }
        let mut err = token.error_unexpected(expected);
        err.cause = self.error.take().map(Box::new);
        err
    }

    /// Add `err` to the current error stack.
    pub(crate) fn set_error(&mut self, mut error: Error) {
        if let Some(prev) = self.error.take() {
            error.cause = Some(Box::new(prev));
        };
        self.error = Some(error);
    }

    /// Returns a special token that is used in place of an error.
    fn error_token(&self) -> Token {
        Token { kind: TokenKind::ParseError, span: self.current_span() }
    }

    /// Get the next token after performing any preprocessing
    pub(crate) fn next(&mut self) -> Token {
        loop {
            let next = match self.peeked.pop_front() {
                Some(token) => token,
                None => self.next_raw(),
            };
            if !self.ignored_tokens.contains(&next.kind) {
                return next;
            }
        }
    }

    /// Without considering any tokens that have been peeked, retreive the next token after
    /// performing any preprocessing.
    fn next_raw(&mut self) -> Token {
        loop {
            let token = match self.lexer_next() {
                Some(token) => token,
                None => return Token { kind: TokenKind::Eof, span: self.current_span() },
            };

            match token.kind {
                TokenKind::Preprocessor(kind) => {
                    let peek_stack = std::mem::take(&mut self.peeked);

                    let prev_ignored = self.ignored_tokens;
                    self.ignored_tokens = &[TokenKind::Comment, TokenKind::Whitespace];

                    if let Err(e) = preprocessor::handle_macro(self, kind) {
                        self.set_error(e);
                        return self.error_token();
                    }

                    self.ignored_tokens = prev_ignored;
                    self.peeked = peek_stack;
                }
                _ if self.state.is_disabled() => {}
                _ => return token,
            }
        }
    }

    /// Gets the next raw token from the underlying lexer
    fn lexer_next(&mut self) -> Option<Token> {
        loop {
            let lexer = self.lexers.last_mut()?;
            let src = &self.sources[lexer.src as usize];

            let Some(token) = lexer.next_token(&src.content, self.lexer_mode)
            else {
                // We are done with this source, remove it from the stack, and continue with the
                // next entry
                self.lexers.pop();
                continue;
            };
            return Some(token);
        }
    }

    /// Peek at the nth token in the token stream
    pub(crate) fn peek_nth(&mut self, mut n: usize) -> Token {
        if self.error.is_some() {
            return self.error_token();
        }

        // Skip over ignored tokens.
        for (i, token) in self.peeked.iter().enumerate() {
            if i > n {
                break;
            }
            if self.ignored_tokens.contains(&token.kind) {
                n += 1;
            }
        }

        // Consume additional tokens if required.
        while self.peeked.len() <= n {
            let next = self.next_raw();
            self.peeked.push_back(next);
            if self.ignored_tokens.contains(&next.kind) {
                n += 1;
            }
        }

        self.peeked[n]
    }

    /// Peek at the next token in the token stream
    pub(crate) fn peek(&mut self) -> Token {
        self.peek_nth(0)
    }

    /// Checks whether the type of the `nth` token from the current lexer in the token stream
    /// matches `kind`
    pub(crate) fn check_nth(&mut self, n: usize, kind: TokenKind) -> bool {
        self.peek_nth(n).kind == kind
    }

    /// Checks whether the type of the next token in the token stream matches `kind`
    pub(crate) fn check(&mut self, kind: TokenKind) -> bool {
        self.check_nth(0, kind)
    }

    /// Checks whether the next token is an ident and equal to this name
    pub(crate) fn check_ident(&mut self, name: &str) -> bool {
        let next = self.peek_nth(0);
        if next.kind != TokenKind::Ident {
            return false;
        }
        self.interner.get((next.span.start, next.span.end)) == name
    }

    /// Expands the token stream associated with `src` at the current location
    pub(crate) fn expand_here(&mut self, src: SourceId) -> Result<(), Error> {
        self.lexers.push(Lexer::new(src));
        if self.lexers.len() >= MAX_EXPANSION_DEPTH {
            let mut error = {
                let span = self.lexers[0].current_span();
                Error { message: String::from("(expanded)"), span, cause: None }
            };
            for lexer in self.lexers.iter().skip(1) {
                let span = lexer.current_span();
                error = error.context(String::from("(expanded)"), span);
            }
            return Err(error.context(
                format!(
                    "Exceeded maximum include depth when expanding: {}",
                    self.sources[src as usize].name
                ),
                self.current_span(),
            ));
        }
        Ok(())
    }

    /// Adds content to sources returning an identifier that can be used to reference the content.
    pub fn load_content(&mut self, name: String, content: String) -> SourceId {
        let src_id = self.sources.len().try_into().expect("Exceeded maximum number of sources.");
        let lines = find_line_offsets(&content);
        self.sources.push(LoadedSource { name, content, lines });
        src_id
    }

    /// Handles loading data for and expanding `@include "<file>"` statements
    pub fn include_file(&mut self, name: impl Into<String>) -> Result<(), Error> {
        let name = name.into();
        let content = self
            .input
            .open(&name)
            .map_err(|e| self.error(format!("failed to open `{}`: {}", name, e)))?;
        let file = self.load_content(name, content);

        self.expand_here(file)
    }

    /// Consume the next token and check that its type matches `kind`
    pub(crate) fn expect(&mut self, kind: TokenKind) -> Result<Token, Error> {
        let token = self.next();
        if token.kind != kind {
            return Err(self.error_unexpected(token, &[kind]));
        }
        Ok(token)
    }

    /// Consume the next token and check that its an ident and matches `name`
    pub(crate) fn expect_ident(&mut self, name: &str) -> Result<(), Error> {
        let token = self.peek();
        let ident: ast::Ident = self.parse()?;
        if self.get_ident_str(ident) != name {
            return Err(self.error_unexpected(token, &[TokenKind::Ident]));
        }
        Ok(())
    }

    /// Consume the next token if it matches `kind`
    pub(crate) fn bump_if(&mut self, kind: TokenKind) -> Result<Option<Token>, Error> {
        if self.check(kind) { Ok(Some(self.next())) } else { Ok(None) }
    }

    pub fn parse<T: Parse>(&mut self) -> Result<T, Error> {
        match self.try_parse::<T>() {
            Ok(Some(inner)) => Ok(inner),
            Ok(None) => Err(self.error(format!("Expected: {}", T::NAME))),
            Err(err) => Err(err),
        }
    }

    pub fn try_parse<T: Parse>(&mut self) -> Result<Option<T>, Error> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }

        let span_start = self.peek().span;
        match T::try_parse(self) {
            Ok(inner) => Ok(inner),
            Err(err) => {
                let span = match err.cause.is_some() {
                    true => err.span,
                    false => Span::new(span_start, self.current_span()),
                };
                Err(Error {
                    message: format!("Error parsing: {}", T::NAME),
                    span,
                    cause: Some(Box::new(err)),
                })
            }
        }
    }

    /// Parse a string from the token stream, returning the string without quote characters
    pub(crate) fn parse_string(&mut self) -> Result<String, Error> {
        let mut token = self.expect(TokenKind::String)?;

        // Adjust the token boundaries to exclude quote characters
        token.span.start += 1;
        token.span.end -= 1;

        Ok(self.get_str(token).into())
    }

    /// Parses either an identifier or a string (excluding the quote characters) as an ast::String.
    pub(crate) fn parse_ident_or_string(&mut self) -> Result<String, Error> {
        let next = self.peek();
        match next.kind {
            TokenKind::String => Ok(self.parse_string()?),
            TokenKind::Ident => {
                let ident = self.expect(TokenKind::Ident)?;
                Ok(self.get_str(ident).into())
            }
            _ => Err(self.error_unexpected(next, &[TokenKind::String, TokenKind::Ident])),
        }
    }

    /// Parses an integer used for storing the size of a token or index operation from the token
    /// stream that must always be decimal encoded.
    pub(crate) fn parse_size(&mut self) -> Result<VarSize, Error> {
        let token = self.expect(TokenKind::Number)?;
        let value = self.get_str(token);
        value.parse().map_err(|e| self.error(format!("invalid u8: {}", e)))
    }

    /// Parses an integer used for defining the size of a field or space. Unlike `parse_size` this
    /// value is allowed to be hex encoded.
    pub(crate) fn parse_size_field(&mut self) -> Result<VarSize, Error> {
        self.parse::<u64>()?.try_into().map_err(|_| self.error("`size` field is too large"))
    }
}

fn find_line_offsets(content: &str) -> Vec<u32> {
    let line_iter = content
        .char_indices()
        .filter(|(_, x)| *x == '\n')
        .map(|(i, _)| u32::try_from(i).expect("file is too large"));
    [0].into_iter().chain(line_iter).collect()
}

pub struct ErrorFormatter<'a> {
    inner: &'a Parser,
    error: Error,
}

impl<'a> std::fmt::Display for ErrorFormatter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::iter;

        if self.inner.sources.is_empty() {
            return write!(f, "error during initialization: {}", self.error.message);
        }

        let span = self.error.span;
        let src = &self.inner.sources[span.src as usize];

        let (line, col) = src.line_and_column(span.start);

        let line_start = src.lines[line] as usize;
        let line_end = *src.lines.get(line + 1).unwrap_or(&(src.content.len() as u32)) as usize;

        writeln!(f, "{}:{}:{} error: {}", src.name, line + 1, col, self.error.message)?;

        let mut span_str = String::new();
        span_str.extend(iter::repeat(' ').take(span.start as usize - line_start));
        span_str.extend(iter::repeat('^').take(self.error.span.len().min(line_end - line_start)));

        writeln!(f, "{}\n{}", &src.content[line_start..line_end], span_str)?;

        let mut error = self.error.cause.as_ref();
        while let Some(inner) = error {
            let src = &self.inner.sources[span.src as usize];
            let (line, col) = src.line_and_column(inner.span.start);
            writeln!(f, "{}:{}:{} {}", src.name, line + 1, col, inner.message)?;
            error = inner.cause.as_ref();
        }

        Ok(())
    }
}

pub trait Parse: Sized {
    const NAME: &'static str;

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error>;
}

impl<T: Parse> Parse for Vec<T> {
    const NAME: &'static str = "Sequence";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let mut list = vec![];
        while let Some(next) = T::try_parse(p)? {
            list.push(next);
        }
        Ok(Some(list))
    }
}

impl<T: Parse> Parse for Option<T> {
    const NAME: &'static str = "Optional";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(Some(T::try_parse(p)?))
    }
}

impl Parse for i64 {
    const NAME: &'static str = "Signed Integer";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let negative = p.bump_if(TokenKind::Minus)?.is_some();
        let Some(value) = u64::try_parse(p)?
        else {
            return Ok(None);
        };
        let mut value = value as i64;
        if negative {
            value = value.wrapping_neg();
        }
        Ok(Some(value))
    }
}

impl Parse for u64 {
    const NAME: &'static str = "Integer";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let token = match p.bump_if(TokenKind::Number)? {
            Some(token) => token,
            None => return Ok(None),
        };

        let value = p.get_str(token);
        let (value, radix) = match (value.strip_prefix("0x"), value.strip_prefix("0b")) {
            (Some(hex), None) => (hex, 16),
            (None, Some(binary)) => (binary, 2),
            _ => (value, 10),
        };

        let trimmed = value.trim_start_matches('0');
        if !value.is_empty() && trimmed.is_empty() {
            // If input was non-empty, and now is empty then the input must be entirely zeros
            return Ok(Some(0));
        }

        Ok(Some(
            u64::from_str_radix(value, radix)
                .map_err(|e| token.error(format!("invalid number: {}", e)))?,
        ))
    }
}

impl Parse for ast::Ident {
    const NAME: &'static str = "Identifier";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        match p.bump_if(TokenKind::Ident)? {
            Some(token) => Ok(Some(Self(p.intern_token(token)))),
            None => Ok(None),
        }
    }
}

impl Parse for ast::Sleigh {
    const NAME: &'static str = "Sleigh";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(Some(ast::Sleigh { items: parse_sequence_until_v2(p, TokenKind::Eof)? }))
    }
}

impl Parse for ast::Item {
    const NAME: &'static str = "Item";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let token = p.peek();
        Ok(match token.kind {
            TokenKind::Define => Some(parse_define(p)?),
            TokenKind::Attach => Some(parse_attach(p)?),
            TokenKind::With => Some(ast::Item::With(p.parse()?)),
            TokenKind::Macro => Some(ast::Item::Macro(p.parse()?)),
            TokenKind::Colon | TokenKind::Ident => Some(ast::Item::Constructor(p.parse()?)),
            _ => None,
        })
    }
}

#[cold]
pub fn parse_define(p: &mut Parser) -> Result<ast::Item, Error> {
    p.expect(TokenKind::Define)?;

    let token = p.peek();
    let define = match token.kind {
        TokenKind::Endian => ast::Item::DefineEndian(p.parse()?),
        TokenKind::Alignment => {
            let alignment = parse_kw_value(p, TokenKind::Alignment)?;
            ast::Item::DefineAlignment(alignment)
        }
        TokenKind::Space => ast::Item::DefineSpace(p.parse()?),
        TokenKind::BitRange => {
            p.expect(TokenKind::BitRange)?;
            let items = parse_sequence_until_v2(p, TokenKind::SemiColon)?;
            ast::Item::DefineBitRange(items)
        }
        TokenKind::PcodeOp => {
            p.expect(TokenKind::PcodeOp)?;
            ast::Item::DefineUserOp(p.parse::<ast::Ident>()?)
        }
        TokenKind::Token => ast::Item::DefineToken(p.parse()?),
        TokenKind::Context => ast::Item::DefineContext(p.parse()?),
        TokenKind::Ident => ast::Item::SpaceNameDef(p.parse()?),
        _ => {
            use TokenKind::*;
            return Err(p.error_unexpected(token, &[
                Endian, Alignment, Space, BitRange, PcodeOp, Token, Context, Ident,
            ]));
        }
    };
    p.expect(TokenKind::SemiColon)?;
    Ok(define)
}

impl Parse for ast::EndianKind {
    const NAME: &'static str = "EndianKind";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if !p.check(TokenKind::Endian) {
            return Ok(None);
        }

        let start = p.current_span();
        let ast::Ident(ident) = parse_kw_value(p, TokenKind::Endian)?;
        let str = p.interner.get(ident);
        Some(str.parse().map_err(|_| Error {
            message: format!("Unexpected endian kind: {}", str),
            span: Span::new(start, p.current_span()),
            cause: None,
        }))
        .transpose()
    }
}

impl Parse for ast::Space {
    const NAME: &'static str = "Space";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Space)?.is_none() {
            return Ok(None);
        }

        let name = p.parse()?;
        let kind = parse_ident_value_v2(p, "type")?;
        let size = parse_ident_value(p, "size", Parser::parse_size_field)?;

        let word_size = match p.check_ident("wordsize") {
            true => Some(parse_ident_value(p, "wordsize", Parser::parse_size_field)?),
            false => None,
        };
        let default = p.bump_if(TokenKind::Default)?.is_some();

        Ok(Some(ast::Space { name, kind, size, word_size, default }))
    }
}

impl Parse for ast::SpaceNameDef {
    const NAME: &'static str = "SpaceName";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let space = p.parse()?;
        let offset = parse_ident_value(p, "offset", Parser::parse::<u64>)?;
        let size = parse_ident_value(p, "size", Parser::parse_size_field)?;
        let names = parse_ident_list(p)?;

        Ok(Some(ast::SpaceNameDef { space, offset, size, names }))
    }
}

impl Parse for ast::SpaceKind {
    const NAME: &'static str = "SpaceKind";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let ast::Ident(ident) = match ast::Ident::try_parse(p)? {
            Some(ident) => ident,
            None => return Ok(None),
        };

        match p.interner.get(ident) {
            "ram_space" => Ok(Some(Self::RamSpace)),
            "rom_space" => Ok(Some(Self::RomSpace)),
            "register_space" => Ok(Some(Self::RegisterSpace)),
            other => Err(p.error(format!("invalid space type: {}", other))),
        }
    }
}

impl Parse for ast::TokenDef {
    const NAME: &'static str = "Token";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Token)?.is_none() {
            return Ok(None);
        }

        let name = p.parse()?;
        p.expect(TokenKind::LeftParen)?;
        let bits = p.parse_size()?;
        p.expect(TokenKind::RightParen)?;
        let endian = p.parse::<Option<ast::EndianKind>>()?;
        let fields = parse_sequence_until_v2(p, TokenKind::SemiColon)?;

        Ok(Some(ast::TokenDef { name, bits, endian, fields }))
    }
}

impl Parse for ast::TokenField {
    const NAME: &'static str = "TokenField";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let name = p.parse()?;
        p.expect(TokenKind::Equal)?;
        let range = parse_field_range(p)?;

        let signed = p.bump_if(TokenKind::Signed)?.is_some();
        let hex = p.bump_if(TokenKind::Hex)?.is_some();
        let dec = p.bump_if(TokenKind::Dec)?.is_some();

        Ok(Some(ast::TokenField { name, range, signed, hex, dec }))
    }
}

impl Parse for ast::Context {
    const NAME: &'static str = "Context";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Context)?.is_none() {
            return Ok(None);
        }

        let name = p.parse()?;
        let fields = parse_sequence_until_v2(p, TokenKind::SemiColon)?;
        Ok(Some(ast::Context { name, fields }))
    }
}

impl Parse for ast::ContextField {
    const NAME: &'static str = "ContextField";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let name = p.parse()?;
        p.expect(TokenKind::Equal)?;
        let range = parse_field_range(p)?;

        let signed = p.bump_if(TokenKind::Signed)?.is_some();
        let hex = p.bump_if(TokenKind::Hex)?.is_some();
        let dec = p.bump_if(TokenKind::Dec)?.is_some();
        let noflow = p.bump_if(TokenKind::NoFlow)?.is_some();

        Ok(Some(ast::ContextField { name, range, signed, hex, dec, noflow }))
    }
}

impl Parse for ast::BitRange {
    const NAME: &'static str = "BitRange";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let (name, (source, range)) =
            parse_key_value(p, |p| Ok((p.parse::<ast::Ident>()?, parse_bit_range(p)?)))?;
        Ok(Some(ast::BitRange { name, source, range }))
    }
}

#[cold]
pub fn parse_attach(p: &mut Parser) -> Result<ast::Item, Error> {
    p.expect(TokenKind::Attach)?;

    let token = p.peek();
    let attach = match token.kind {
        TokenKind::Variables => ast::Item::AttachVariables(p.parse()?),
        TokenKind::Names => ast::Item::AttachNames(p.parse()?),
        TokenKind::Values => ast::Item::AttachValues(p.parse()?),
        _ => {
            use TokenKind::*;
            return Err(p.error_unexpected(token, &[Variables, Names, Values]));
        }
    };
    p.expect(TokenKind::SemiColon)?;
    Ok(attach)
}

impl Parse for ast::AttachVariables {
    const NAME: &'static str = "AttachVariables";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Variables)?.is_none() {
            return Ok(None);
        }
        let fields = parse_ident_list(p)?;
        let registers = parse_ident_list(p)?;
        Ok(Some(ast::AttachVariables { fields, registers }))
    }
}

impl Parse for ast::AttachNames {
    const NAME: &'static str = "AttachNames";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Names)?.is_none() {
            return Ok(None);
        }
        let fields = parse_ident_list(p)?;
        let names = parse_item_or_list(p, Parser::parse_ident_or_string)?;
        Ok(Some(ast::AttachNames { fields, names }))
    }
}

impl Parse for ast::AttachValues {
    const NAME: &'static str = "AttachValues";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Values)?.is_none() {
            return Ok(None);
        }
        let fields = parse_ident_list(p)?;
        let ItemOrList(values) = p.parse()?;
        Ok(Some(ast::AttachValues { fields, values }))
    }
}

impl Parse for ast::WithDef {
    const NAME: &'static str = "with";

    #[cold]
    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::With)?.is_none() {
            return Ok(None);
        }

        let table = if !p.check(TokenKind::Colon) { Some(p.parse()?) } else { None };
        p.expect(TokenKind::Colon)?;
        let constraint = p.parse()?;

        let disasm_actions = p.try_parse::<BrackedList<_>>()?.map_or(vec![], |x| x.0);
        p.expect(TokenKind::LeftBrace)?;
        let items = parse_sequence_until_v2(p, TokenKind::RightBrace)?;
        p.expect(TokenKind::RightBrace)?;
        Ok(Some(ast::WithDef { table, constraint, disasm_actions, items }))
    }
}

impl Parse for ast::Macro {
    const NAME: &'static str = "Macro";

    #[cold]
    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::Macro)?.is_none() {
            return Ok(None);
        }

        let name = p.parse()?;
        p.expect(TokenKind::LeftParen)?;

        let mut prev_comma = true;
        let params = parse_sequence(p, |p| {
            if !prev_comma || p.check(TokenKind::RightParen) {
                return Ok(None);
            }

            let ident = p.parse()?;
            prev_comma = p.bump_if(TokenKind::Comma)?.is_some();

            Ok(Some(ident))
        })?;

        p.expect(TokenKind::RightParen)?;

        p.expect(TokenKind::LeftBrace)?;
        let body = parse_sequence_until_v2(p, TokenKind::RightBrace)?;
        p.expect(TokenKind::RightBrace)?;

        Ok(Some(ast::Macro { name, params, body }))
    }
}

impl Parse for ast::Constructor {
    const NAME: &'static str = "Constructor";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let start = p.peek().span;

        let table = if !p.check(TokenKind::Colon) { Some(p.parse()?) } else { None };
        p.expect(TokenKind::Colon)?;

        // Between the table header and the `is` expression whitespace is meaningful so enable
        // whitespace in the parser
        p.ignored_tokens = &[TokenKind::Comment];
        p.lexer_mode = lexer::Mode::Display;

        let mnemonic = match p.peek().kind {
            TokenKind::Ident | TokenKind::String => Some(p.parse_ident_or_string()?),
            TokenKind::Whitespace => {
                p.expect(TokenKind::Whitespace)?;
                None
            }
            _ => None,
        };

        let display = parse_display_section(p)?;
        p.expect(TokenKind::Is)?;

        // Reset lexer mode.
        p.ignored_tokens = &[TokenKind::Comment, TokenKind::Whitespace, TokenKind::Line];
        p.lexer_mode = lexer::Mode::Normal;

        let constraint = p.parse()?;
        let disasm_actions = p.try_parse::<BrackedList<_>>()?.map_or(vec![], |x| x.0);

        let token = p.peek();
        let semantics = match token.kind {
            TokenKind::Unimpl => {
                p.expect(TokenKind::Unimpl)?;
                vec![ast::Statement::Unimplemented]
            }
            TokenKind::LeftBrace => {
                p.expect(TokenKind::LeftBrace)?;
                let statements = parse_sequence_until_v2(p, TokenKind::RightBrace)?;
                p.expect(TokenKind::RightBrace)?;
                statements
            }
            _ => return Err(p.error_unexpected(token, &[TokenKind::Unimpl, TokenKind::LeftBrace])),
        };

        Ok(Some(ast::Constructor {
            table,
            mnemonic,
            display,
            constraint,
            disasm_actions,
            semantics,
            span: Span::new(start, p.current_span()),
        }))
    }
}

impl Parse for ast::ConstraintExpr {
    const NAME: &'static str = "ConstraintExpr";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(Some(parse_constraint_expr_bp(p, 0)?))
    }
}

fn constraint_op_bp(token: Token) -> Option<(ast::ConstraintOp, u8, u8)> {
    Some(match token.kind {
        TokenKind::Ampersand => (ast::ConstraintOp::And, 5, 6),
        TokenKind::Bar => (ast::ConstraintOp::Or, 3, 4),
        TokenKind::SemiColon => (ast::ConstraintOp::Concat, 2, 1),
        _ => return None,
    })
}

/// Parse a constraint expression using a Pratt parser with the specified minimum binding power
fn parse_constraint_expr_bp(p: &mut Parser, min_bp: u8) -> Result<ast::ConstraintExpr, Error> {
    let mut lhs = parse_constraint(p)?;

    loop {
        let token = p.peek();
        let (op, lhs_bp, rhs_bp) = match constraint_op_bp(token) {
            Some(inner) => inner,
            None => return Ok(lhs),
        };

        // The next operation has lower precedence than the one on the stack, so return the current
        // left-hand-side expression as the right-hand-side of the expression on the stack
        if lhs_bp < min_bp {
            return Ok(lhs);
        }

        // Consume the token associated with the op
        p.next();

        // Parse the right-hand-side expression
        let rhs = parse_constraint_expr_bp(p, rhs_bp)?;
        lhs = ast::ConstraintExpr::Op(Box::new(lhs), op, Box::new(rhs));
    }
}

/// Parses a single constraint (or a parenthesized complex constraint) from the parser
fn parse_constraint(p: &mut Parser) -> Result<ast::ConstraintExpr, Error> {
    let token = p.peek();
    let mut expr = match token.kind {
        TokenKind::TripleDot => {
            p.expect(TokenKind::TripleDot)?;
            ast::ConstraintExpr::ExtendLeft(Box::new(parse_constraint(p)?))
        }

        TokenKind::Ident => {
            let ident = p.parse::<ast::Ident>()?;
            match p.peek().kind {
                TokenKind::ExclamationMark => {
                    p.expect(TokenKind::ExclamationMark)?;
                    p.expect(TokenKind::Equal)?;
                    let constraint = parse_constraint_operand(p)?;
                    ast::ConstraintExpr::Cmp(ident, ast::ConstraintCmp::NotEqual, constraint)
                }
                TokenKind::Equal => {
                    p.expect(TokenKind::Equal)?;
                    let constraint = parse_constraint_operand(p)?;
                    ast::ConstraintExpr::Cmp(ident, ast::ConstraintCmp::Equal, constraint)
                }
                TokenKind::LessThan => {
                    p.expect(TokenKind::LessThan)?;
                    let cmp = match p.bump_if(TokenKind::Equal)?.is_some() {
                        true => ast::ConstraintCmp::LessOrEqual,
                        false => ast::ConstraintCmp::Less,
                    };
                    let constraint = parse_constraint_operand(p)?;
                    ast::ConstraintExpr::Cmp(ident, cmp, constraint)
                }
                TokenKind::GreaterThan => {
                    p.expect(TokenKind::GreaterThan)?;
                    let cmp = match p.bump_if(TokenKind::Equal)?.is_some() {
                        true => ast::ConstraintCmp::GreaterOrEqual,
                        false => ast::ConstraintCmp::Greater,
                    };
                    let constraint = parse_constraint_operand(p)?;
                    ast::ConstraintExpr::Cmp(ident, cmp, constraint)
                }
                _ => ast::ConstraintExpr::Ident(ident),
            }
        }

        TokenKind::LeftParen => {
            p.expect(TokenKind::LeftParen)?;
            let inner = parse_constraint_expr_bp(p, 0)?;
            p.expect(TokenKind::RightParen)?;
            inner
        }

        _ => return Err(p.error_unexpected(token, &[TokenKind::Ident, TokenKind::LeftParen])),
    };

    if p.check(TokenKind::TripleDot) {
        p.expect(TokenKind::TripleDot)?;
        expr = ast::ConstraintExpr::ExtendRight(Box::new(expr));
    }

    Ok(expr)
}

fn parse_constraint_operand(p: &mut Parser) -> Result<ast::PatternExpr, Error> {
    parse_pattern_expr(p, false)
}

fn parse_display_section(p: &mut Parser) -> Result<Vec<ast::DisplaySegment>, Error> {
    let start = p.current_span();
    let mut items = parse_sequence(p, |p| {
        macro_rules! lit {
            ($value:expr) => {{
                p.next();
                Some(ast::DisplaySegment::Literal($value.into()))
            }};
        }
        let token = p.peek();
        Ok(match token.kind {
            TokenKind::Whitespace => lit!(" "),
            TokenKind::Line => lit!(""),
            TokenKind::Hat => lit!(""),
            TokenKind::LeftParen => lit!("("),
            TokenKind::RightParen => lit!(")"),
            TokenKind::Ident => Some(p.parse::<ast::Ident>()?.into()),
            TokenKind::String => Some(p.parse_string()?.into()),
            TokenKind::Is => None,
            TokenKind::Eof => {
                return Err(Error {
                    message: "Unexpected EOF when parsing display section".into(),
                    span: Span::new(start, token.span),
                    cause: None,
                });
            }
            TokenKind::RawLiteral => {
                let token = p.next();
                Some(p.get_str(token).into())
            }
            _ => return Err(p.error_unexpected(token, &[])),
        })
    })?;

    // Trim trailing whitespace
    if let Some(ast::DisplaySegment::Literal(x)) = items.last() {
        if x == " " {
            items.pop();
        }
    }

    Ok(items)
}

impl Parse for ast::Statement {
    const NAME: &'static str = "Statement";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let stmt = match p.peek().kind {
            TokenKind::Export => {
                p.expect(TokenKind::Export)?;
                let value = p.parse()?;
                ast::Statement::Export { value }
            }
            TokenKind::Local => {
                p.expect(TokenKind::Local)?;
                let name = p.parse()?;
                let size = parse_optional_size(p)?;

                if p.bump_if(TokenKind::Equal)?.is_some() {
                    let expr = p.parse()?;
                    ast::Statement::LocalAssignment { name, size, expr }
                }
                else {
                    ast::Statement::Local { name, size }
                }
            }
            TokenKind::Build => {
                p.expect(TokenKind::Build)?;
                let name = p.parse()?;
                ast::Statement::Build { name }
            }
            TokenKind::Star => {
                let (space, size, pointer) = parse_deref(p)?;
                p.expect(TokenKind::Equal)?;
                let value = p.parse()?;
                ast::Statement::Store { space, size, pointer, value }
            }
            TokenKind::If => {
                p.expect(TokenKind::If)?;
                let cond = parse_pcode_term(p)?;
                p.expect(TokenKind::Goto)?;
                let dst = p.parse()?;
                ast::Statement::CondBranch { cond, dst, hint: ast::BranchHint::Jump }
            }
            TokenKind::Goto => {
                p.expect(TokenKind::Goto)?;
                ast::Statement::Branch { dst: p.parse()?, hint: ast::BranchHint::Jump }
            }
            TokenKind::Call => {
                p.expect(TokenKind::Call)?;
                ast::Statement::Branch { dst: p.parse()?, hint: ast::BranchHint::Call }
            }
            TokenKind::Return => {
                p.expect(TokenKind::Return)?;
                ast::Statement::Branch { dst: p.parse()?, hint: ast::BranchHint::Return }
            }
            TokenKind::LessThan => {
                p.expect(TokenKind::LessThan)?;
                let label = p.parse()?;
                p.expect(TokenKind::GreaterThan)?;
                // Labels do not end with a semi-colon so exit early here
                return Ok(Some(ast::Statement::Label { label }));
            }
            TokenKind::Ident if p.check_nth(1, TokenKind::LeftParen) => {
                ast::Statement::Call(p.parse()?)
            }
            _ => {
                let lhs = parse_pcode_term(p)?;
                p.expect(TokenKind::Equal)?;
                let rhs = p.parse()?;
                ast::Statement::Copy { to: lhs, from: rhs }
            }
        };
        p.expect(TokenKind::SemiColon)?;
        Ok(Some(stmt))
    }
}

fn parse_deref(
    p: &mut Parser,
) -> Result<(Option<ast::Ident>, Option<VarSize>, ast::PcodeExpr), Error> {
    p.expect(TokenKind::Star)?;
    let space = match p.bump_if(TokenKind::LeftBracket)?.is_some() {
        true => {
            let ident = p.parse()?;
            p.expect(TokenKind::RightBracket)?;
            Some(ident)
        }
        false => None,
    };
    let size = parse_optional_size(p)?;
    let pointer = parse_pcode_term(p)?;
    Ok((space, size, pointer))
}

impl Parse for ast::PcodeCall {
    const NAME: &'static str = "Call";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        let name = p.parse()?;
        p.expect(TokenKind::LeftParen)?;

        let mut prev_comma = true;
        let args = parse_sequence(p, |p| {
            if !prev_comma || p.check(TokenKind::RightParen) {
                return Ok(None);
            }

            let expr = p.parse()?;
            prev_comma = p.bump_if(TokenKind::Comma)?.is_some();

            Ok(Some(expr))
        })?;
        p.expect(TokenKind::RightParen)?;

        Ok(Some(ast::PcodeCall { name, args }))
    }
}

impl Parse for ast::BranchDst {
    const NAME: &'static str = "BranchDestination";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(match p.peek().kind {
            TokenKind::Ident | TokenKind::Number => Some(ast::BranchDst::Direct(p.parse()?)),
            TokenKind::LeftBracket => {
                p.expect(TokenKind::LeftBracket)?;
                let offset = p.parse()?;
                p.expect(TokenKind::RightBracket)?;
                Some(ast::BranchDst::Indirect(offset))
            }
            TokenKind::LessThan => {
                p.expect(TokenKind::LessThan)?;
                let label = p.parse()?;
                p.expect(TokenKind::GreaterThan)?;
                Some(ast::BranchDst::Label(label))
            }
            _ => None,
        })
    }
}

impl Parse for ast::JumpLabel {
    const NAME: &'static str = "JumpLabel";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(match p.peek().kind {
            TokenKind::Ident => Some(ast::JumpLabel::Ident(p.parse()?)),
            TokenKind::Number => {
                let offset = p.parse()?;
                let size = parse_optional_size(p)?.ok_or_else(|| p.error("expected size"))?;
                Some(ast::JumpLabel::Integer(offset, size))
            }
            _ => None,
        })
    }
}

impl Parse for ast::PcodeExpr {
    const NAME: &'static str = "PcodeExpr";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(Some(parse_pcode_expr_bp(p, 0)?))
    }
}

fn parse_pcode_expr_bp(p: &mut Parser, min_bp: u8) -> Result<ast::PcodeExpr, Error> {
    let mut lhs = parse_pcode_term(p)?;

    loop {
        let (op, tokens, (lhs_bp, rhs_bp)) = match pcode_infix_bp(p)? {
            Some(inner) => inner,
            None => return Ok(lhs),
        };

        // The next operation has lower precedence than the one on the stack, so return the current
        // left-hand-side expression as the right-hand-side of the expression on the stack
        if lhs_bp < min_bp {
            return Ok(lhs);
        }

        // Consume the tokens associated with the op
        for _ in 0..tokens {
            p.next();
        }

        // Parse the right-hand-side expression
        let rhs = parse_pcode_expr_bp(p, rhs_bp)?;
        lhs = ast::PcodeExpr::Op { a: Box::new(lhs), op, b: Box::new(rhs) };
    }
}

fn pcode_infix_bp(p: &mut Parser) -> Result<Option<(ast::PcodeOp, usize, (u8, u8))>, Error> {
    use TokenKind::*;

    let token = p.peek();
    Ok(Some(match token.kind {
        Star => (ast::PcodeOp::IntMult, 1, (9, 10)),
        FStar => (ast::PcodeOp::FloatMult, 1, (9, 10)),
        ForwardSlash => (ast::PcodeOp::IntDiv, 1, (9, 10)),
        SForwardSlash => (ast::PcodeOp::IntSignedDiv, 1, (9, 10)),
        FForwardSlash => (ast::PcodeOp::FloatDiv, 1, (9, 10)),
        Percent => (ast::PcodeOp::IntRem, 1, (9, 10)),
        SPercent => (ast::PcodeOp::IntSignedRem, 1, (9, 10)),

        Plus => (ast::PcodeOp::IntAdd, 1, (7, 8)),
        FPlus => (ast::PcodeOp::FloatAdd, 1, (7, 8)),
        Minus => (ast::PcodeOp::IntSub, 1, (7, 8)),
        FMinus => (ast::PcodeOp::FloatSub, 1, (7, 8)),

        LessThan if p.check_nth(1, LessThan) => (ast::PcodeOp::IntLeft, 2, (5, 6)),
        GreaterThan if p.check_nth(1, GreaterThan) => (ast::PcodeOp::IntRight, 2, (5, 6)),
        SGreaterThan if p.check_nth(1, GreaterThan) => (ast::PcodeOp::IntSignedRight, 2, (5, 6)),

        LessThan if p.check_nth(1, Equal) => (ast::PcodeOp::IntLessEqual, 2, (3, 4)),
        LessThan => (ast::PcodeOp::IntLess, 1, (3, 4)),
        SLessThan if p.check_nth(1, Equal) => (ast::PcodeOp::IntSignedLessEqual, 2, (3, 4)),
        SLessThan => (ast::PcodeOp::IntSignedLess, 1, (3, 4)),
        FLessThan if p.check_nth(1, Equal) => (ast::PcodeOp::FloatLessEqual, 2, (3, 4)),
        FLessThan => (ast::PcodeOp::FloatLess, 1, (3, 4)),

        GreaterThan if p.check_nth(1, Equal) => (ast::PcodeOp::IntGreaterEqual, 2, (3, 4)),
        GreaterThan => (ast::PcodeOp::IntGreater, 1, (3, 4)),
        SGreaterThan if p.check_nth(1, Equal) => (ast::PcodeOp::IntSignedGreaterEqual, 2, (3, 4)),
        SGreaterThan => (ast::PcodeOp::IntSignedGreater, 1, (3, 4)),
        FGreaterThan if p.check_nth(1, Equal) => (ast::PcodeOp::FloatGreaterEqual, 2, (3, 4)),
        FGreaterThan => (ast::PcodeOp::FloatGreater, 1, (3, 4)),

        Equal if p.check_nth(1, TokenKind::Equal) => (ast::PcodeOp::IntEqual, 2, (3, 4)),
        ExclamationMark if p.check_nth(1, TokenKind::Equal) => {
            (ast::PcodeOp::IntNotEqual, 2, (3, 4))
        }
        FEqual if p.check_nth(1, TokenKind::Equal) => (ast::PcodeOp::FloatEqual, 2, (3, 4)),
        TokenKind::FExclamationMark if p.check_nth(1, TokenKind::Equal) => {
            (ast::PcodeOp::FloatNotEqual, 2, (3, 4))
        }

        Bar if p.check_nth(1, Bar) => (ast::PcodeOp::BoolOr, 2, (1, 2)),
        Bar => (ast::PcodeOp::IntOr, 1, (1, 2)),
        Hat if p.check_nth(1, Hat) => (ast::PcodeOp::BoolXor, 2, (1, 2)),
        Hat => (ast::PcodeOp::IntXor, 1, (1, 2)),
        Ampersand if p.check_nth(1, Ampersand) => (ast::PcodeOp::BoolAnd, 2, (1, 2)),
        Ampersand => (ast::PcodeOp::IntAnd, 1, (1, 2)),

        _ => return Ok(None),
    }))
}

fn parse_pcode_term(p: &mut Parser) -> Result<ast::PcodeExpr, Error> {
    macro_rules! prefix_op {
        ($kind:expr, $name:expr) => {{
            p.expect($kind)?;
            let arg = parse_pcode_term(p)?;
            let id = p.interner.intern($name);
            Ok(ast::PcodeExpr::Call(ast::PcodeCall { name: ast::Ident(id), args: vec![arg] }))
        }};
    }

    let token = p.peek();
    let expr = match token.kind {
        TokenKind::Ampersand => {
            p.expect(TokenKind::Ampersand)?;
            let size = parse_optional_size(p)?;
            let value = p.parse().context("required because of `&`", token.span)?;
            return Ok(ast::PcodeExpr::AddressOf { size, value });
        }
        TokenKind::Star => {
            let (space, size, pointer) = parse_deref(p)?;
            return Ok(ast::PcodeExpr::Deref { space, size, pointer: Box::new(pointer) });
        }
        TokenKind::ExclamationMark => return prefix_op!(TokenKind::ExclamationMark, "!"),
        TokenKind::Tilde => return prefix_op!(TokenKind::Tilde, "~"),
        TokenKind::Minus => return prefix_op!(TokenKind::Minus, "-"),
        TokenKind::FMinus => return prefix_op!(TokenKind::FMinus, "f-"),
        TokenKind::Ident => {
            if p.check_nth(1, TokenKind::LeftParen) {
                return Ok(ast::PcodeExpr::Call(p.parse()?));
            }
            ast::PcodeExpr::Ident { value: p.parse()? }
        }
        TokenKind::Number => ast::PcodeExpr::Integer { value: p.parse()? },
        TokenKind::LeftParen => {
            p.expect(TokenKind::LeftParen)?;
            let inner = p.parse()?;
            p.expect(TokenKind::RightParen)?;
            inner
        }
        _ => {
            use TokenKind::*;
            return Err(Error {
                message: "Error parsing: Pcode terminal expression".to_string(),
                span: Span::new(token.span, p.current_span()),
                cause: Some(Box::new(
                    p.error_unexpected(token, &[Ampersand, Star, Minus, Ident, Number, LeftParen]),
                )),
            });
        }
    };

    let token = p.peek();
    match token.kind {
        TokenKind::Colon => {
            let size = parse_optional_size(p)?.unwrap();
            Ok(ast::PcodeExpr::Truncate { value: Box::new(expr), size })
        }
        TokenKind::LeftBracket => {
            let range = parse_bit_range(p)?;
            Ok(ast::PcodeExpr::SliceBits { value: Box::new(expr), range })
        }
        _ => Ok(expr),
    }
}

impl Parse for ast::DisasmAction {
    const NAME: &'static str = "DisassemblyAction";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(match p.peek().kind {
            TokenKind::Ident => {
                let ident = p.parse()?;
                p.expect(TokenKind::Equal)?;
                let expr = parse_disasm_expr(p)?;
                p.expect(TokenKind::SemiColon)?;
                Some(ast::DisasmAction::Assignment { ident, expr })
            }
            TokenKind::GlobalSet => {
                p.expect(TokenKind::GlobalSet)?;
                p.expect(TokenKind::LeftParen)?;
                let start_sym = p.parse()?;
                p.expect(TokenKind::Comma)?;
                let context_sym = p.parse()?;
                p.expect(TokenKind::RightParen)?;
                p.expect(TokenKind::SemiColon)?;
                Some(ast::DisasmAction::GlobalSet { start_sym, context_sym })
            }
            _ => None,
        })
    }
}

fn parse_disasm_expr(p: &mut Parser) -> Result<ast::PatternExpr, Error> {
    parse_pattern_expr(p, true)
}

fn parse_pattern_expr(p: &mut Parser, allow_symbols: bool) -> Result<ast::PatternExpr, Error> {
    parse_pattern_expr_b(p, 0, allow_symbols)
}

fn pattern_op_bp(
    p: &mut Parser,
    allow_symbols: bool,
) -> Result<Option<(ast::PatternOp, usize, (u8, u8))>, Error> {
    use TokenKind::*;

    let token = p.peek();
    Ok(Some(match token.kind {
        Plus => (ast::PatternOp::Add, 1, (3, 4)),
        Minus => (ast::PatternOp::Sub, 1, (3, 4)),

        Bar if allow_symbols => (ast::PatternOp::Or, 1, (5, 6)),
        Or => (ast::PatternOp::Or, 1, (5, 6)),

        Hat if allow_symbols => (ast::PatternOp::Xor, 1, (5, 6)),
        Xor => (ast::PatternOp::Xor, 1, (5, 6)),

        Ampersand if allow_symbols => (ast::PatternOp::And, 1, (5, 6)),
        And => (ast::PatternOp::And, 1, (5, 6)),

        Star => (ast::PatternOp::Mult, 1, (7, 8)),
        ForwardSlash => (ast::PatternOp::Div, 1, (7, 8)),

        LessThan if p.check_nth(1, LessThan) => (ast::PatternOp::IntLeft, 2, (9, 10)),
        GreaterThan if p.check_nth(1, GreaterThan) => (ast::PatternOp::IntRight, 2, (9, 10)),
        _ => return Ok(None),
    }))
}

fn parse_pattern_expr_b(
    p: &mut Parser,
    min_bp: u8,
    allow_symbols: bool,
) -> Result<ast::PatternExpr, Error> {
    let mut lhs = parse_disasm_term(p, allow_symbols)?;

    loop {
        let (op, tokens, (lhs_bp, rhs_bp)) = match pattern_op_bp(p, allow_symbols)? {
            Some(inner) => inner,
            None => return Ok(lhs),
        };

        // The next operation has lower precedence than the one on the stack, so return the current
        // left-hand-side expression as the right-hand-side of the expression on the stack
        if lhs_bp < min_bp {
            return Ok(lhs);
        }

        // Consume the tokens associated with the op
        for _ in 0..tokens {
            p.next();
        }

        // Parse the right-hand-side expression
        let rhs = parse_pattern_expr_b(p, rhs_bp, allow_symbols)?;
        lhs = ast::PatternExpr::Op(Box::new(lhs), op, Box::new(rhs));
    }
}

fn parse_disasm_term(p: &mut Parser, allow_symbols: bool) -> Result<ast::PatternExpr, Error> {
    let token = p.peek();
    match token.kind {
        TokenKind::Ident => Ok(ast::PatternExpr::Ident(p.parse()?)),
        TokenKind::Number => Ok(ast::PatternExpr::Integer(p.parse()?)),
        TokenKind::Minus => {
            p.expect(TokenKind::Minus)?;
            let inner = parse_pattern_expr_b(p, 10, allow_symbols)?;
            Ok(ast::PatternExpr::Negate(Box::new(inner)))
        }
        TokenKind::Tilde => {
            p.expect(TokenKind::Tilde)?;
            let inner = parse_pattern_expr_b(p, 10, allow_symbols)?;
            Ok(ast::PatternExpr::Not(Box::new(inner)))
        }
        TokenKind::LeftParen => {
            p.expect(TokenKind::LeftParen)?;
            let inner = parse_pattern_expr_b(p, 0, allow_symbols)?;
            p.expect(TokenKind::RightParen)?;
            Ok(inner)
        }
        _ => {
            use TokenKind::*;
            Err(p.error_unexpected(token, &[Ident, Number, Tilde, LeftParen]))
        }
    }
}

/// Parses an optional size expression e.g. `:8`
fn parse_optional_size(p: &mut Parser) -> Result<Option<VarSize>, Error> {
    Ok(match p.bump_if(TokenKind::Colon)?.is_some() {
        true => Some(p.parse_size()?),
        false => None,
    })
}

fn parse_field_range(p: &mut Parser) -> Result<ast::Range, Error> {
    p.expect(TokenKind::LeftParen)?;
    let a = p.parse_size()?;
    p.expect(TokenKind::Comma)?;
    let b = p.parse_size()?;
    p.expect(TokenKind::RightParen)?;
    Ok((a, b))
}

fn parse_bit_range(p: &mut Parser) -> Result<ast::Range, Error> {
    p.expect(TokenKind::LeftBracket)?;
    let a = p.parse_size()?;
    p.expect(TokenKind::Comma)?;
    let b = p.parse_size()?;
    p.expect(TokenKind::RightBracket)?;
    Ok((a, b))
}

fn parse_kw_value<T: Parse>(p: &mut Parser, kw: TokenKind) -> Result<T, Error> {
    p.expect(kw)?;
    p.expect(TokenKind::Equal)?;
    p.parse()
}

fn parse_ident_value<T>(
    p: &mut Parser,
    kw: &str,
    mut parse_value: impl FnMut(&mut Parser) -> Result<T, Error>,
) -> Result<T, Error> {
    p.expect_ident(kw)?;
    p.expect(TokenKind::Equal)?;
    let value = parse_value(p)?;
    Ok(value)
}

fn parse_ident_value_v2<T: Parse>(p: &mut Parser, kw: &str) -> Result<T, Error> {
    p.expect_ident(kw)?;
    p.expect(TokenKind::Equal)?;
    p.parse()
}

fn parse_key_value<T>(
    p: &mut Parser,
    mut parse_value: impl FnMut(&mut Parser) -> Result<T, Error>,
) -> Result<(ast::Ident, T), Error> {
    let key = p.parse()?;
    p.expect(TokenKind::Equal)?;
    let value = parse_value(p)?;
    Ok((key, value))
}

fn parse_sequence<T>(
    p: &mut Parser,
    mut item: impl FnMut(&mut Parser) -> Result<Option<T>, Error>,
) -> Result<Vec<T>, Error> {
    let mut list = vec![];
    while let Some(next) = item(p)? {
        list.push(next);
    }
    Ok(list)
}

fn parse_sequence_until<T>(
    p: &mut Parser,
    end: TokenKind,
    mut item: impl FnMut(&mut Parser) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    parse_sequence(p, |p| if p.check(end) { Ok(None) } else { Ok(Some(item(p)?)) })
}

/// Parse elements of type `T` until we reach a token of type `end`
fn parse_sequence_until_v2<T: Parse>(p: &mut Parser, end: TokenKind) -> Result<Vec<T>, Error> {
    let mut list = vec![];
    while !p.check(end) {
        list.push(p.parse::<T>()?);
    }
    Ok(list)
}

fn parse_bracketed_list<T>(
    p: &mut Parser,
    item: impl FnMut(&mut Parser) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    p.expect(TokenKind::LeftBracket)?;
    let list = parse_sequence_until(p, TokenKind::RightBracket, item)?;
    p.expect(TokenKind::RightBracket)?;
    Ok(list)
}

struct BrackedList<T>(Vec<T>);

impl<T: Parse> Parse for BrackedList<T> {
    const NAME: &'static str = "BrackedList";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if p.bump_if(TokenKind::LeftBracket)?.is_none() {
            return Ok(None);
        }
        let list = parse_sequence_until_v2(p, TokenKind::RightBracket)?;
        p.expect(TokenKind::RightBracket)?;
        Ok(Some(Self(list)))
    }
}

fn parse_item_or_list<T>(
    p: &mut Parser,
    mut item: impl FnMut(&mut Parser) -> Result<T, Error>,
) -> Result<Vec<T>, Error> {
    use TokenKind::LeftBracket;
    if p.check(LeftBracket) { parse_bracketed_list(p, item) } else { Ok(vec![item(p)?]) }
}

enum Either<A, B> {
    A(A),
    B(B),
}

impl<A: Parse, B: Parse> Parse for Either<A, B> {
    const NAME: &'static str = "Either";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        if let Some(a) = A::try_parse(p)? {
            return Ok(Some(Self::A(a)));
        }
        if let Some(b) = B::try_parse(p)? {
            return Ok(Some(Self::B(b)));
        }
        Ok(None)
    }
}

struct ItemOrList<T: Parse>(Vec<T>);

impl<T: Parse> Parse for ItemOrList<T> {
    const NAME: &'static str = "ItemOrList";

    fn try_parse(p: &mut Parser) -> Result<Option<Self>, Error> {
        Ok(match <Either<T, BrackedList<T>>>::try_parse(p)? {
            Some(Either::A(ident)) => Some(Self(vec![ident])),
            Some(Either::B(BrackedList(list))) => Some(Self(list)),
            None => None,
        })
    }
}

fn parse_ident_list(p: &mut Parser) -> Result<Vec<ast::Ident>, Error> {
    parse_item_or_list(p, Parser::parse)
}
