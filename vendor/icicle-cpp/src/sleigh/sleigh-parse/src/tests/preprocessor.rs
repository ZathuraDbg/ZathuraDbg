use crate::{lexer::TokenKind, parser::Parser};

fn preprocess_to_string(content: &str) -> Result<String, String> {
    let mut parser = Parser::from_str(content);

    let mut tokens = vec![];
    loop {
        let token = parser.next();
        if token.kind == TokenKind::Eof || parser.error.is_some() {
            break;
        }
        tokens.push(token);
    }

    if let Some(e) = parser.error.take() {
        let msg = format!("{}", parser.error_formatter(e));
        eprintln!("{}", msg);
        return Err(msg);
    }

    eprintln!("{:?}", tokens);

    let mut output = String::new();
    for token in tokens {
        output.push_str(parser.get_str(token));
        output.push_str(" ");
    }
    output.pop();

    Ok(output)
}

/// Tests that the `@define` macro works and macros and be expanded correctly
#[test]
fn define_simple() {
    let result = preprocess_to_string(
        r#"
@define ENDIAN "big"
define endian=$(ENDIAN);
"#,
    );

    assert_eq!(result.unwrap(), "define endian = big ;");
}

#[test]
fn define_nothing() {
    let result = preprocess_to_string(
        r#"
@define ENDIAN
@ifdef ENDIAN
define endian=big;
@endif
"#,
    );

    assert_eq!(result.unwrap(), "define endian = big ;");
}

/// Tests that the `@define` macro works with integer values
#[test]
fn define_integer() {
    let result = preprocess_to_string(
        r#"
@define XLEN 8
define register offset=0x1000 size=$(XLEN) [ pc ];
"#,
    );

    assert_eq!(result.unwrap(), "define register offset = 0x1000 size = 8 [ pc ] ;");
}

/// Tests that `ifdef` works correctly
#[test]
fn ifdef() {
    let result = preprocess_to_string(
        r#"
@define ENDIAN "big"
@ifdef ENDIAN
define endian=$(ENDIAN);
@endif
"#,
    );

    assert_eq!(result.unwrap(), "define endian = big ;");
}

/// Tests that `ifdef` works correctly with an else case
#[test]
fn ifdef_else() {
    let result = preprocess_to_string(
        r#"
@ifdef ENDIAN
define endian=$(ENDIAN);
@else
define endian=little;
@endif
"#,
    );

    assert_eq!(result.unwrap(), "define endian = little ;");
}

/// Tests that nested `ifdef` statements work correctly
#[test]
fn nested() {
    let result = preprocess_to_string(
        r#"
@define A "10"
@ifdef A
@ ifdef A
a
@ else
b
@ endif
@else
@ ifdef A
a
@ else
b
@ endif
@endif
"#,
    );

    assert_eq!(result.unwrap(), "a");
}

/// Tests that the preprocessor ignores macros in comments
#[test]
fn in_comment() {
    let result = preprocess_to_string(
        r#"
@define ENDIAN "big"
# @define ENDIAN "little"
define endian=$(ENDIAN);# $(ENDIAN)
"#,
    );

    assert_eq!(result.unwrap(), "define endian = big ;");
}

/// Test that the preprocessor ignores macros in strings
#[test]
fn in_string() {
    let result = preprocess_to_string(
        r#"
@define ENDIAN "big"
define a = "@ifdef ENDIAN";
define endian=$(ENDIAN);
define b = "$(ENDIAN)";
"#,
    );

    assert_eq!(
        result.unwrap(),
        r#"define a = "@ifdef ENDIAN" ; define endian = big ; define b = "$(ENDIAN)" ;"#
    );
}

#[test]
fn if_defined() {
    let result = preprocess_to_string(
        r#"
@define TEST "true"

@if defined(TEST)
@define VALUE "test_is_defined"
@else
@define VALUE "test_is_not_defined"
@endif

define endian = $(VALUE);
"#,
    );

    assert_eq!(result.unwrap(), "define endian = test_is_defined ;");
}

#[test]
fn if_expr() {
    let result = preprocess_to_string(
        r#"
@define TEST "true"

@if (defined(TEST) && (TEST != "not_true" && TEST == "true"))
@define VALUE "test_is_defined"
@else
@define VALUE "test_is_not_defined"
@endif

define endian = $(VALUE);
"#,
    );

    assert_eq!(result.unwrap(), "define endian = test_is_defined ;");
}

#[test]
fn elif_expr() {
    let result = preprocess_to_string(
        r#"
@define TEST "true"

@if TEST == "not_true"
@define VALUE "bad"
@elif TEST == "not_true2"
@define VALUE "bad"
@elif TEST == "true"
@define VALUE "good"
@else
@define VALUE "bad"
@endif

define endian = $(VALUE);
"#,
    );

    assert_eq!(result.unwrap(), "define endian = good ;");
}

#[test]
fn detect_recursive_expansion() {
    let result = preprocess_to_string(
        r#"
@define TEST1 "$(TEST2)"
@define TEST2 "$(TEST3)"
@define TEST3 "$(TEST1)"

define endian = $(TEST1);
"#,
    );

    assert!(result.is_err());
}

#[test]
fn or_expr() {
    let result = preprocess_to_string(
        r#"
@define Carry "F[0,1]"

r = (r << 1) | $(Carry);
"#,
    );

    assert_eq!(result.unwrap(), "r = ( r < < 1 ) | F [ 0 , 1 ] ;");
}
