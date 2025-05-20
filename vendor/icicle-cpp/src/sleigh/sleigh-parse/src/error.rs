use crate::lexer::SourceId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub src: SourceId,
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: Span, end: Span) -> Self {
        if start.src != end.src {
            eprintln!(
                "[WARNING] trying to compute span that crosses source boundaries: start={:?}, end={:?}",
                start, end
            )
        }

        Self { src: start.src, start: start.start, end: end.end }
    }

    pub fn len(&self) -> usize {
        if self.start >= self.end {
            return 1;
        }
        (self.end - self.start + 1) as usize
    }

    pub fn range(&self) -> std::ops::Range<usize> {
        self.start as usize..(self.end as usize + 1)
    }

    pub fn none() -> Self {
        Self { src: 0, start: 0, end: 0 }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    /// The error message to display to the user
    pub message: String,

    /// The span associated with this error message
    pub span: Span,

    /// A lower level error message that caused this error
    pub cause: Option<Box<Error>>,
}

pub trait ErrorExt: Sized {
    /// Add additional context to the error by specifing that `msg` should be displayed for `span`
    fn context(self, msg: impl Into<String>, span: Span) -> Self;

    /// Add additional context to the error by specifing that `msg` should be displayed for `span`
    fn with_context(self, func: impl FnOnce() -> (String, Span)) -> Self {
        let (msg, span) = func();
        self.context(msg, span)
    }
}

impl ErrorExt for Error {
    fn context(self, msg: impl Into<String>, span: Span) -> Self {
        Self { message: msg.into(), span, cause: Some(Box::new(self)) }
    }
}

impl<T> ErrorExt for Result<T, Error> {
    fn context(self, msg: impl Into<String>, span: Span) -> Self {
        self.map_err(|cause| cause.context(msg, span))
    }

    fn with_context(self, func: impl FnOnce() -> (String, Span)) -> Self {
        self.map_err(|cause| {
            let (msg, span) = func();
            cause.context(msg, span)
        })
    }
}
