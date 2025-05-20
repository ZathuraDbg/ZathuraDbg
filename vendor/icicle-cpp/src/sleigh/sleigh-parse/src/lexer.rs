use crate::{error::Error, Span};

pub type SourceId = u32;

#[derive(Copy, Clone, Debug)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn error(&self, msg: impl Into<String>) -> Error {
        Error { message: msg.into(), span: self.span, cause: None }
    }

    /// Create a new error message for an unexpected token kind error
    #[cold]
    pub fn error_unexpected(&self, expected: &[TokenKind]) -> Error {
        assert!(!expected.contains(&self.kind));

        let message = match self.kind {
            TokenKind::UnclosedString if expected == [TokenKind::String] => {
                String::from("Unterminated string")
            }
            TokenKind::Eof => format!("Unexpected end of file (expected: {:?})", expected),
            _ => format!("Unexpected token: {:?} (expected {:?})", self.kind, expected),
        };

        self.error(message)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) enum MacroKind {
    Include,
    Define,
    Undef,
    If,
    IfDef,
    IfNotDef,
    Else,
    Elif,
    EndIf,
    Expand,
    Unknown,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum TokenKind {
    Preprocessor(MacroKind),
    Defined,

    // A symbol for one or more white-space characters
    Whitespace,

    // End of line character
    Line,

    // End of file
    Eof,

    Comment,

    // Keywords
    Define,
    Alignment,
    Endian,
    BitRange,
    Space,
    Default,

    PcodeOp,
    Attach,
    Token,
    Context,
    Variables,
    Names,
    Values,

    Signed,
    Hex,
    Dec,
    NoFlow,

    With,
    Macro,

    Unimpl,
    TripleDot,

    // Special identifiers for table expressions
    GlobalSet,
    Export,
    Local,
    Build,
    If,
    Goto,
    Call,
    Return,

    Is,
    And,
    Or,
    Xor,

    // Symbols
    Plus,
    Minus,
    Star,
    ForwardSlash,
    Percent,
    Hat,
    Bar,
    Ampersand,
    ExclamationMark,
    Tilde,
    Equal,
    LessThan,
    GreaterThan,
    SemiColon,
    Colon,
    Comma,
    LeftBrace,
    RightBrace,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
    AtSign,

    // Multi character symbols
    FMinus,
    FPlus,
    FForwardSlash,
    FStar,
    FLessThan,
    FGreaterThan,
    FExclamationMark,
    FEqual,
    SForwardSlash,
    SPercent,
    SLessThan,
    SGreaterThan,

    Ident,

    // Literals
    String,
    Number,
    RawLiteral, // Any other literal parsed as part of the display section.

    // Errors
    UnclosedString,
    Unknown,
    ParseError,
}

impl From<MacroKind> for TokenKind {
    fn from(v: MacroKind) -> Self {
        TokenKind::Preprocessor(v)
    }
}

/// The mode the lexer should parse tokens in. Used to enable context specific parsing of the
/// display section.
#[derive(Copy, Clone)]
pub enum Mode {
    Normal,
    Display,
}

pub(crate) struct Lexer {
    /// An identifier corresponding to the source associated with this lexer
    pub src: SourceId,

    /// The position of the lexer inside of the current input.
    offset: usize,

    /// The character offset of the start of the current line.
    line_start: u32,

    /// The offset inside of `input` of the start of the current token.
    token_start: u32,

    /// The offset of the most recent character processed
    prev: u32,
}

impl Lexer {
    pub fn new(src: SourceId) -> Self {
        Self { src, line_start: 0, offset: 0, token_start: 0, prev: 0 }
    }

    /// Lex the next token from the input stream
    pub fn next_token(&mut self, input: &str, mode: Mode) -> Option<Token> {
        let value = input.get(self.offset..)?.chars().next()?;
        self.token_start = self.offset.try_into().expect("Exceeded max file size.");
        Some(match mode {
            Mode::Normal => self.next_normal_token(input, value),
            Mode::Display => self.next_display_token(input, value),
        })
    }

    /// Lex the next token as a normal token.
    pub fn next_normal_token(&mut self, input: &str, value: char) -> Token {
        match value {
            // Line-ending characters
            '\n' | '\r' => {
                self.eat_line_end(input);
                self.line_start = self.token_start;
                self.create_token(TokenKind::Line)
            }

            // Any other whitespace characters
            c if c.is_whitespace() => {
                self.eat_whitespace(input);
                self.create_token(TokenKind::Whitespace)
            }

            // Comments start with the '#' character and continue to the end of the line.
            '#' => {
                self.eat_line(input);
                self.create_token(TokenKind::Comment)
            }

            // Symbols
            '+' => self.bump_symbol(input, TokenKind::Plus),
            '-' => self.bump_symbol(input, TokenKind::Minus),
            '*' => self.bump_symbol(input, TokenKind::Star),
            '/' => self.bump_symbol(input, TokenKind::ForwardSlash),
            '%' => self.bump_symbol(input, TokenKind::Percent),
            '^' => self.bump_symbol(input, TokenKind::Hat),
            '|' => self.bump_symbol(input, TokenKind::Bar),
            '&' => self.bump_symbol(input, TokenKind::Ampersand),
            '!' => self.bump_symbol(input, TokenKind::ExclamationMark),
            '~' => self.bump_symbol(input, TokenKind::Tilde),
            '=' => self.bump_symbol(input, TokenKind::Equal),
            '<' => self.bump_symbol(input, TokenKind::LessThan),
            '>' => self.bump_symbol(input, TokenKind::GreaterThan),
            ';' => self.bump_symbol(input, TokenKind::SemiColon),
            ',' => self.bump_symbol(input, TokenKind::Comma),
            '{' => self.bump_symbol(input, TokenKind::LeftBrace),
            '}' => self.bump_symbol(input, TokenKind::RightBrace),
            '(' => self.bump_symbol(input, TokenKind::LeftParen),
            ')' => self.bump_symbol(input, TokenKind::RightParen),
            '[' => self.bump_symbol(input, TokenKind::LeftBracket),
            ']' => self.bump_symbol(input, TokenKind::RightBracket),
            ':' => self.bump_symbol(input, TokenKind::Colon),

            // Preprocessor macros.
            '@' => {
                // This is a macro if there is only whitespaces before it
                let line_start = &input[self.line_start as usize..self.token_start as usize];
                self.bump(input);
                if line_start.chars().all(char::is_whitespace) {
                    // Additional whitespace is allowed before the macro name (e.g. `@  if <cond>`)
                    self.eat_whitespace(input);

                    let ident_span = self.eat_ident(input);
                    let kind = match &input[ident_span] {
                        "include" => MacroKind::Include,
                        "define" => MacroKind::Define,
                        "undef" => MacroKind::Undef,
                        "if" => MacroKind::If,
                        "ifdef" => MacroKind::IfDef,
                        "ifndef" => MacroKind::IfNotDef,
                        "else" => MacroKind::Else,
                        "elif" => MacroKind::Elif,
                        "endif" => MacroKind::EndIf,
                        _ => MacroKind::Unknown,
                    };
                    self.create_token(kind)
                }
                else {
                    self.create_token(TokenKind::AtSign)
                }
            }

            // Special keywords (e.g. $xor) or macro expansions (e.g. $(IDENT))
            '$' => {
                self.bump(input);

                if self.peek_char(input) == Some('(') {
                    // Macro expansion
                    self.create_token(MacroKind::Expand)
                }
                else {
                    // Special keyword
                    let ident_span = self.eat_ident(input);
                    let kind = match &input[ident_span] {
                        "and" => TokenKind::And,
                        "or" => TokenKind::Or,
                        "xor" => TokenKind::Xor,
                        _ => TokenKind::Unknown,
                    };
                    self.create_token(kind)
                }
            }

            // String literal
            '"' => match self.eat_string(input) {
                true => self.create_token(TokenKind::String),
                false => self.create_token(TokenKind::UnclosedString),
            },

            // Numeric literal
            '0'..='9' => {
                self.eat_ident(input);
                self.create_token(TokenKind::Number)
            }

            // Keyword or identifier
            '_' | '.' | 'a'..='z' | 'A'..='Z' => {
                let ident_span = self.eat_ident(input);
                let kind = match &input[ident_span] {
                    "defined" => TokenKind::Defined,

                    "define" => TokenKind::Define,
                    "alignment" => TokenKind::Alignment,
                    "endian" => TokenKind::Endian,
                    "bitrange" => TokenKind::BitRange,
                    "space" => TokenKind::Space,
                    "default" => TokenKind::Default,

                    "pcodeop" => TokenKind::PcodeOp,
                    "attach" => TokenKind::Attach,
                    "token" => TokenKind::Token,
                    "context" => TokenKind::Context,
                    "variables" => TokenKind::Variables,
                    "names" => TokenKind::Names,
                    "values" => TokenKind::Values,

                    "signed" => TokenKind::Signed,
                    "hex" => TokenKind::Hex,
                    "dec" => TokenKind::Dec,
                    "noflow" => TokenKind::NoFlow,

                    "unimpl" => TokenKind::Unimpl,
                    "..." => TokenKind::TripleDot,
                    "with" => TokenKind::With,
                    "macro" => TokenKind::Macro,

                    "globalset" => TokenKind::GlobalSet,
                    "export" => TokenKind::Export,
                    "local" => TokenKind::Local,
                    "build" => TokenKind::Build,
                    "if" => TokenKind::If,
                    "goto" => TokenKind::Goto,
                    "call" => TokenKind::Call,
                    "return" => TokenKind::Return,

                    "is" => TokenKind::Is,

                    // Multi-character symbols
                    "f" if self.peek_char(input).map_or(false, |x| "-+/*<>!=".contains(x)) => {
                        match self.bump(input).unwrap() {
                            '-' => TokenKind::FMinus,
                            '+' => TokenKind::FPlus,
                            '/' => TokenKind::FForwardSlash,
                            '*' => TokenKind::FStar,
                            '<' => TokenKind::FLessThan,
                            '>' => TokenKind::FGreaterThan,
                            '!' => TokenKind::FExclamationMark,
                            '=' => TokenKind::FEqual,
                            _ => unreachable!(),
                        }
                    }
                    "s" if self.peek_char(input).map_or(false, |x| "/%<>".contains(x)) => {
                        match self.bump(input).unwrap() {
                            '/' => TokenKind::SForwardSlash,
                            '%' => TokenKind::SPercent,
                            '<' => TokenKind::SLessThan,
                            '>' => TokenKind::SGreaterThan,
                            _ => unreachable!(),
                        }
                    }

                    _ => TokenKind::Ident,
                };

                self.create_token(kind)
            }

            _ => {
                self.bump(input);
                self.create_token(TokenKind::Unknown)
            }
        }
    }

    /// Lex the next display section token.
    pub fn next_display_token(&mut self, input: &str, value: char) -> Token {
        match value {
            // Line-ending characters
            '\n' | '\r' => {
                self.eat_line_end(input);
                self.line_start = self.token_start;
                self.create_token(TokenKind::Line)
            }

            // Any other whitespace characters
            c if c.is_whitespace() => {
                self.eat_whitespace(input);
                self.create_token(TokenKind::Whitespace)
            }

            // String literal
            '"' => match self.eat_string(input) {
                true => self.create_token(TokenKind::String),
                false => self.create_token(TokenKind::UnclosedString),
            },

            // Macro expansions (e.g. $(IDENT))
            '$' => {
                self.bump(input);
                match self.peek_char(input) {
                    Some('(') => self.create_token(MacroKind::Expand),
                    _ => self.create_token(TokenKind::RawLiteral),
                }
            }
            '(' => self.bump_symbol(input, TokenKind::LeftParen),
            ')' => self.bump_symbol(input, TokenKind::RightParen),
            '^' => self.bump_symbol(input, TokenKind::Hat),

            // String or identifier.
            '_' | '.' | 'a'..='z' | 'A'..='Z' => {
                let ident_span = self.eat_ident(input);
                let kind = match &input[ident_span] {
                    "is" => TokenKind::Is,
                    _ => TokenKind::Ident,
                };
                self.create_token(kind)
            }

            _ => {
                self.bump(input);
                self.create_token(TokenKind::RawLiteral)
            }
        }
    }

    /// Gets the location with the current token
    pub fn current_span(&self) -> Span {
        Span { src: self.src, start: self.token_start, end: self.prev }
    }

    /// Create a new token of type `kind` at the current location
    fn create_token(&self, kind: impl Into<TokenKind>) -> Token {
        Token { kind: kind.into(), span: self.current_span() }
    }

    /// Bump a single character and create new token of type `kind` at the current location
    fn bump_symbol(&mut self, input: &str, kind: TokenKind) -> Token {
        self.bump(input);
        self.create_token(kind)
    }

    /// Gets the char from the input stream, updating the lexer's metadata that is used for keeping
    /// track of the next span
    #[inline(always)]
    fn bump(&mut self, input: &str) -> Option<char> {
        let val = input[self.offset..].chars().next()?;
        self.prev = self.offset.try_into().ok()?;
        self.offset += val.len_utf8();
        Some(val)
    }

    /// Peeks at the next char to be processed
    fn peek_char(&mut self, input: &str) -> Option<char> {
        input[self.offset..].chars().next()
    }

    /// Bumps the current offset if the character matches `value`. Returns `true` on a match
    fn bump_if(&mut self, input: &str, value: char) -> bool {
        match self.peek_char(input) {
            Some(x) if x == value => {
                self.bump(input);
                true
            }
            _ => false,
        }
    }

    /// Eat the end of a line, correctly handling different line endings
    fn eat_line_end(&mut self, input: &str) {
        self.bump_if(input, '\r');
        self.bump_if(input, '\n');
    }

    /// Eat the rest of the line
    fn eat_line(&mut self, input: &str) {
        self.bump_while(input, |c| c != '\n' && c != '\r');
    }

    /// Skip characters while `predicate` is true
    fn bump_while(&mut self, input: &str, mut predicate: impl FnMut(char) -> bool) {
        while let Some(next) = self.peek_char(input) {
            if !predicate(next) {
                break;
            }
            self.bump(input);
        }
    }

    /// Eat any whitespace characters except for new line characters
    fn eat_whitespace(&mut self, input: &str) {
        self.bump_while(input, |c| c.is_whitespace() && c != '\r' && c != '\n');
    }

    /// Eat a valid identifier returning
    fn eat_ident(&mut self, input: &str) -> std::ops::RangeInclusive<usize> {
        /// Identifiers are made up of letters a-z, capitals A-Z, digits 0-9 and the characters '.'
        /// and '_'. An identifier can use these characters in any order and for any length, but it
        /// must not start with a digit.
        #[inline(always)]
        fn is_ident_char(c: char) -> bool {
            if !c.is_ascii() {
                return false;
            }

            // abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890._
            match c as u8 {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' => true,
                _ => false,
            }
        }

        if !self.bump(input).map_or(false, is_ident_char) {
            panic!("called `eat_ident` at an invalid location");
        }

        let start = self.prev;
        self.bump_while(input, is_ident_char);
        (start as usize)..=(self.prev as usize)
    }

    /// Eat a string surrounded by `"` characters
    fn eat_string(&mut self, input: &str) -> bool {
        assert_eq!(self.bump(input), Some('"'));
        self.bump_while(input, |c| c != '"' && c != '\n' && c != '\r');
        self.bump_if(input, '"')
    }
}

#[cfg(test)]
fn tokenize_all(input: &str) -> Vec<TokenKind> {
    let mut lexer = Lexer::new(0);
    let mut tokens = vec![];
    while let Some(token) = lexer.next_token(input, Mode::Normal) {
        tokens.push(token.kind);
    }
    tokens
}

#[test]
fn parse_ident() {
    let token = tokenize_all("ident.123.ABC")[0];
    assert_eq!(token, TokenKind::Ident);

    let token = tokenize_all(".IDENT_123_abc")[0];
    assert_eq!(token, TokenKind::Ident);

    let token = tokenize_all("123_invalid_ident")[0];
    assert_ne!(token, TokenKind::Ident);
}

#[test]
fn parse_comment() {
    let tokens = tokenize_all("# this is a comment");
    assert_eq!(tokens, vec![TokenKind::Comment]);

    let tokens = tokenize_all("# this is a\n# multi-line comment\nident.123.ABC");
    assert_eq!(tokens, vec![
        TokenKind::Comment,
        TokenKind::Line,
        TokenKind::Comment,
        TokenKind::Line,
        TokenKind::Ident
    ]);
}

#[test]
fn parse_multi_character_tokens() {
    let check = |input: &str, expected: TokenKind| {
        let tokens: Vec<_> =
            tokenize_all(input).into_iter().filter(|&x| x != TokenKind::Whitespace).collect();
        assert_eq!(tokens, vec![TokenKind::Ident, expected, TokenKind::Ident]);
    };

    check("a f- b", TokenKind::FMinus);
    check("a f+ b", TokenKind::FPlus);
    check("a f/ b", TokenKind::FForwardSlash);
    check("a f* b", TokenKind::FStar);
    check("a f< b", TokenKind::FLessThan);
    check("a f> b", TokenKind::FGreaterThan);
    check("a f! b", TokenKind::FExclamationMark);
    check("a f= b", TokenKind::FEqual);
    check("a s/ b", TokenKind::SForwardSlash);
    check("a s% b", TokenKind::SPercent);
    check("a s< b", TokenKind::SLessThan);
    check("a s> b", TokenKind::SGreaterThan);
}
