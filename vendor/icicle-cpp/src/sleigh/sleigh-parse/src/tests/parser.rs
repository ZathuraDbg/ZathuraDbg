use crate::{
    ast::{self, ParserDisplay},
    parser::Parser,
};

struct ParseResult<T> {
    parser: Parser,
    ast: T,
}

impl<T> ParseResult<T> {
    fn ident(&self, name: &str) -> ast::Ident {
        ast::Ident(self.parser.interner.lookup(name).expect("Unknown Identifier"))
    }
}

impl<T> std::fmt::Display for ParseResult<T>
where
    T: ParserDisplay,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ast.fmt(f, &self.parser)
    }
}

fn parse<T: crate::parser::Parse>(input: &str) -> ParseResult<T> {
    let mut parser = Parser::from_str(input);

    match parser.parse::<T>() {
        Ok(ast) => ParseResult { parser, ast },
        Err(e) => {
            let dbg = format!("{:?}", e);
            let msg = format!("{}", parser.error_formatter(e));
            eprintln!("{}", msg);
            panic!("{}", dbg)
        }
    }
}

macro_rules! check_item_inner {
    ($result:expr, $($path:ident).+$([$index:expr])?, $kind:path, $expected:expr) => {{
        let inner = match &($result).ast.$($path)*$([$index])? {
            $kind(inner) => inner,
            item => panic!("unexpected item: {}", item.display(&$result.parser)),
        };
        assert_eq!(inner, &$expected);
    }};
}

#[test]
fn basic_definitions() {
    let result = parse::<ast::Sleigh>("define endian=big; define endian=little;");
    assert!(matches!(result.ast.items[0], ast::Item::DefineEndian(ast::EndianKind::Big)));
    assert!(matches!(result.ast.items[1], ast::Item::DefineEndian(ast::EndianKind::Little)));

    let result = parse::<ast::Sleigh>("define alignment=32;");
    assert!(matches!(result.ast.items[0], ast::Item::DefineAlignment(32)));

    let result = parse::<ast::Sleigh>("define space ram type=ram_space size=4 default;");
    check_item_inner!(result, items[0], ast::Item::DefineSpace, ast::Space {
        name: result.ident("ram"),
        kind: ast::SpaceKind::RamSpace,
        size: 4,
        word_size: None,
        default: true,
    });

    let result = parse::<ast::Sleigh>("define space register type=register_space size=4;");
    check_item_inner!(result, items[0], ast::Item::DefineSpace, ast::Space {
        name: result.ident("register"),
        kind: ast::SpaceKind::RegisterSpace,
        size: 4,
        word_size: None,
        default: false,
    });
}

#[test]
fn named_registers() {
    let result = parse::<ast::Sleigh>("define register offset=0x4000 size=4 contextreg;");
    check_item_inner!(result, items[0], ast::Item::SpaceNameDef, ast::SpaceNameDef {
        space: result.ident("register"),
        offset: 0x4000,
        size: 4,
        names: vec![result.ident("contextreg")]
    });

    let result = parse::<ast::Sleigh>("define register offset=0 size=4 [ r0 r1 r2 r3 ];");
    check_item_inner!(result, items[0], ast::Item::SpaceNameDef, ast::SpaceNameDef {
        space: result.ident("register"),
        offset: 0,
        size: 4,
        names: vec![result.ident("r0"), result.ident("r1"), result.ident("r2"), result.ident("r3")]
    });

    let result = parse::<ast::Sleigh>("define register offset=0 size=4 [ AL AH _ _ CL CH _ _ ];");
    check_item_inner!(result, items[0], ast::Item::SpaceNameDef, ast::SpaceNameDef {
        space: result.ident("register"),
        offset: 0,
        size: 4,
        names: vec!["AL", "AH", "_", "_", "CL", "CH", "_", "_"]
            .into_iter()
            .map(|x| result.ident(x))
            .collect()
    });
}

#[test]
fn hex_number_in_define() {
    let result = parse::<ast::Sleigh>("define space register type=register_space size=0x4;");
    check_item_inner!(result, items[0], ast::Item::DefineSpace, ast::Space {
        name: result.ident("register"),
        kind: ast::SpaceKind::RegisterSpace,
        size: 4,
        word_size: None,
        default: false,
    });

    let result = parse::<ast::Sleigh>("define register offset=0x0 size=0x4 [ r0 r1 r2 r3 ];");
    check_item_inner!(result, items[0], ast::Item::SpaceNameDef, ast::SpaceNameDef {
        space: result.ident("register"),
        offset: 0,
        size: 4,
        names: vec![result.ident("r0"), result.ident("r1"), result.ident("r2"), result.ident("r3")]
    });
}

#[test]
fn bit_range() {
    let result = parse::<ast::Sleigh>(
        "define bitrange zf=statusreg[10,1] cf=statusreg[11,1] sf=statusreg[12,1];",
    );

    check_item_inner!(result, items[0], ast::Item::DefineBitRange, vec![
        ast::BitRange {
            name: result.ident("zf"),
            source: result.ident("statusreg"),
            range: (10, 1)
        },
        ast::BitRange {
            name: result.ident("cf"),
            source: result.ident("statusreg"),
            range: (11, 1)
        },
        ast::BitRange {
            name: result.ident("sf"),
            source: result.ident("statusreg"),
            range: (12, 1)
        }
    ]);
}

#[test]
fn user_defined_op() {
    let result = parse::<ast::Sleigh>("define pcodeop arctan;");
    check_item_inner!(result, items[0], ast::Item::DefineUserOp, result.ident("arctan"));
}

#[test]
fn define_token() {
    let result = parse::<ast::Sleigh>(
        r#"
define token instr(8)
    rt          = (16,20)
    rs          = (21,25)
    off26       = (0,25) signed # 26 bit signed offset
;
"#,
    );

    check_item_inner!(result, items[0], ast::Item::DefineToken, ast::TokenDef {
        name: result.ident("instr"),
        bits: 8,
        endian: None,
        fields: vec![
            ast::TokenField {
                name: result.ident("rt"),
                range: (16, 20),
                signed: false,
                hex: false,
                dec: false,
            },
            ast::TokenField {
                name: result.ident("rs"),
                range: (21, 25),
                signed: false,
                hex: false,
                dec: false,
            },
            ast::TokenField {
                name: result.ident("off26"),
                range: (0, 25),
                signed: true,
                hex: false,
                dec: false,
            },
        ]
    });

    let result = parse::<ast::Sleigh>(
        r#"
define token test(32) endian = little
    a = (16,20);
"#,
    );
    check_item_inner!(result, items[0], ast::Item::DefineToken, ast::TokenDef {
        name: result.ident("test"),
        bits: 32,
        endian: Some(ast::EndianKind::Little),
        fields: vec![ast::TokenField {
            name: result.ident("a"),
            range: (16, 20),
            signed: false,
            hex: false,
            dec: false,
        }]
    })
}

#[test]
fn define_context() {
    let result = parse::<ast::Sleigh>(
        r#"
define context contextreg
    field1=(0,0) noflow
    field2=(0,0) signed noflow
;
"#,
    );

    check_item_inner!(result, items[0], ast::Item::DefineContext, ast::Context {
        name: result.ident("contextreg"),
        fields: vec![
            ast::ContextField {
                name: result.ident("field1"),
                range: (0, 0),
                signed: false,
                hex: false,
                dec: false,
                noflow: true,
            },
            ast::ContextField {
                name: result.ident("field2"),
                range: (0, 0),
                signed: true,
                hex: false,
                dec: false,
                noflow: true,
            }
        ]
    });
}

#[test]
fn attach() {
    let result = parse::<ast::Sleigh>(r#"attach variables [ a b c ] [ r0 r1 r2 ];"#);
    check_item_inner!(result, items[0], ast::Item::AttachVariables, ast::AttachVariables {
        fields: vec![result.ident("a"), result.ident("b"), result.ident("c")],
        registers: vec![result.ident("r0"), result.ident("r1"), result.ident("r2")],
    });

    let result = parse::<ast::Sleigh>(r#"attach names hint [ "load" "store" ];"#);
    check_item_inner!(result, items[0], ast::Item::AttachNames, ast::AttachNames {
        fields: vec![result.ident("hint")],
        names: vec!["load".into(), "store".into()],
    });
}

#[test]
fn macros() {
    let result = parse::<ast::Sleigh>(
        r#"
macro MemDestCast(dest, src) {
    *(dest) = src;
}"#,
    );
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        "macro MemDestCast(dest, src) { *:(dest) = src; }"
    );
}

#[test]
fn basic_constructors() {
    let result = parse::<ast::Sleigh>(r#"fmt1: "S"  is format=0x10 {}"#);
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        "fmt1: S is format=0x10 { }"
    );

    let result = parse::<ast::Sleigh>(":mul RD, RS32src, RT32src  is epsilon & a=1 {}");
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        ":mul RD, RS32src, RT32src is epsilon & a=0x1 { }"
    );
}

#[test]
fn complex_constructors() {
    let result = parse::<ast::Sleigh>(
        r#": aa^"("^bb^")" is bb & cc=0x1 & dd=0x0 & ee & ff=0x1 & ((gg>=0x0 & gg<=0x2) | (gg>=0x4 & gg<=0xF)) ; hh ; aa { }"#,
    );
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        ": aa(bb) is (((((bb & cc=0x1) & dd=0x0) & ee) & ff=0x1) & ((gg>=0x0 & gg<=0x2) | (gg>=0x4 & gg<=0xf))) ; (hh ; aa) { }"
    );
}

#[test]
fn constructor_export() {
    let result = parse::<ast::Sleigh>(
        r#"fcvt_vmnemonic: "fcvtas" is b_29=0 & b_23=0 & b_1314=0b10 & b_12=0 { export 0:1; }"#,
    );
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        "fcvt_vmnemonic: fcvtas is ((b_29=0x0 & b_23=0x0) & b_1314=0x2) & b_12=0x0 { export 0x0:1; }"
    );
}

#[test]
fn symbols_in_display_segment() {
    let result = parse::<ast::Sleigh>(r#"test: {0+-*:,()[]"hello"!~=} is a=0 {}"#);
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        "test: {0+-*:,()[]hello!~=} is a=0x0 { }"
    );
}

#[test]
fn atsign_in_display_section() {
    let result = parse::<ast::Sleigh>(r#"test: @"@" is a=0 {}"#);
    assert_eq!(result.ast.items[0].display(&result.parser).to_string(), "test: @@ is a=0x0 { }");
}

#[test]
fn keyword_in_display_section() {
    let result = parse::<ast::Sleigh>(r#"test:call call is a=0 {}"#);
    assert_eq!(
        result.ast.items[0].display(&result.parser).to_string(),
        "test:call call is a=0x0 { }"
    );
}

#[test]
fn macro_in_display_segment() {
    let result = parse::<ast::Sleigh>(
        r#"
    @define NOTVLE "vle=0"
    test: $(NOTVLE) is a=0 {}
"#,
    );
    assert_eq!(result.ast.items[0].display(&result.parser).to_string(), "test: vle=0 is a=0x0 { }");

    let result = parse::<ast::Sleigh>(
        r##"
        @define HASH "#"
        test: $(HASH) is a=0x0 { }
"##,
    );
    assert_eq!(result.ast.items[0].display(&result.parser).to_string(), "test: # is a=0x0 { }");
}

#[test]
fn hash_in_display_section() {
    let result = parse::<ast::Sleigh>(r##"test: #"#" is a=0 {}"##);
    assert_eq!(result.ast.items[0].display(&result.parser).to_string(), "test: ## is a=0x0 { }");
}

#[test]
fn constraint_binding_power() {
    let result = parse::<ast::ConstraintExpr>("op=0x2 & mod=0x3 ; op2=0x3 & mod3=0x4");
    assert_eq!(result.to_string(), "(op=0x2 & mod=0x3) ; (op2=0x3 & mod3=0x4)");
}

#[test]
fn constraint_or_expr() {
    let result = parse::<ast::ConstraintExpr>(
        "ISA_MODE=0 & ((prime=0x2F & REL6=0) | (prime=0x1F & REL6=1 & fct=0x25 & bit6=0)) & OFF_BASER6 & op",
    );

    assert_eq!(
        result.to_string(),
        "((ISA_MODE=0x0 & ((prime=0x2f & REL6=0x0) | (((prime=0x1f & REL6=0x1) & fct=0x25) & bit6=0x0))) & OFF_BASER6) & op"
    );
}

#[test]
fn constraint_groups() {
    let result = parse::<ast::ConstraintExpr>(r"a=0 & c=1; d=2; e=3");
    assert_eq!(result.to_string(), "(a=0x0 & c=0x1) ; (d=0x2 ; e=0x3)");

    let result = parse::<ast::ConstraintExpr>(
        "vexMode=0 & prefix_66=1 & byte=0x0F; byte=0x6E; rm32 & XmmReg ...",
    );
    assert_eq!(
        result.to_string(),
        "((vexMode=0x0 & prefix_66=0x1) & byte=0xf) ; (byte=0x6e ; (rm32 & ((XmmReg) ...)))"
    );

    let result = parse::<ast::ConstraintExpr>(r"(a=0; c & d=2) & e");
    assert_eq!(result.to_string(), "(a=0x0 ; (c & d=0x2)) & e");
}

#[test]
fn variable_length() {
    let result = parse::<ast::ConstraintExpr>("a=0 & (b=0x01; c=0x02) ... & instruction ...");
    assert_eq!(result.to_string(), "(a=0x0 & ((b=0x1 ; c=0x2) ...)) & ((instruction) ...)");

    let result = parse::<ast::ConstraintExpr>(
        "instrPhase=0 & (byte=0x0f; byte=0x0f; XmmReg ... & m64; Suffix3D) ... & instruction ...",
    );
    assert_eq!(
        result.to_string(),
        "(instrPhase=0x0 & ((byte=0xf ; (byte=0xf ; ((((XmmReg) ...) & m64) ; Suffix3D))) ...)) & ((instruction) ...)"
    );
}

#[test]
fn disasm_action() {
    let result =
        parse::<ast::DisasmAction>("reloc=((inst_start+4) $and 0xfffffffff0000000) | 4*ind26;");
    assert_eq!(
        result.to_string(),
        "reloc = ((inst_start + 0x4) & 0xfffffffff0000000) | (0x4 * ind26)"
    );

    let result = parse::<ast::DisasmAction>("globalset(inst_next, addrsize);");
    assert_eq!(result.to_string(), "globalset(inst_next, addrsize)");

    let result = parse::<ast::DisasmAction>("sim = (b_22 * (-1<<9));");
    assert_eq!(result.to_string(), "sim = b_22 * (-0x1 << 0x9)");

    let result = parse::<ast::DisasmAction>("a = b <<  5 | c;");
    assert_eq!(result.to_string(), "a = (b << 0x5) | c");

    let result = parse::<ast::DisasmAction>("a = ~((-1 << ((b - c) & 0x3f)) << 1);");
    assert_eq!(result.to_string(), "a = ~((-0x1 << ((b - c) & 0x3f)) << 0x1)");
}

#[test]
fn disasm_action_with_missing_semicolon() {
    let result = parse::<ast::Constructor>(r"test: is a=0 [a = 1;] {}");
    assert_eq!(result.ast.display(&result.parser).to_string(), "test:  is a=0x0 [ a = 0x1;] { }");

    let result = Parser::from_str("a = 1").parse::<ast::DisasmAction>();
    assert!(result.is_err());

    let result = Parser::from_str(r"test: is a=0 [a = 1] {}").parse::<ast::Constructor>();
    assert!(result.is_err());
}

#[test]
fn pcode_expr() {
    let expr = parse::<ast::PcodeExpr>("push22(0x10)");
    assert_eq!(
        expr.ast,
        ast::PcodeExpr::Call(ast::PcodeCall {
            name: expr.ident("push22"),
            args: vec![ast::PcodeExpr::Integer { value: 0x10 }]
        })
    );
}

#[test]
fn pcode_address_of() {
    let expr = parse::<ast::PcodeExpr>("&:2 inst_next");
    assert_eq!(expr.ast, ast::PcodeExpr::AddressOf {
        size: Some(2),
        value: expr.ident("inst_next")
    });

    let expr = parse::<ast::PcodeExpr>("&r1 + 4");
    assert_eq!(expr.to_string(), "&r1 + 0x4");

    let expr = parse::<ast::PcodeExpr>("&r1 + ident");
    assert_eq!(expr.to_string(), "&r1 + ident");
}

#[test]
fn pcode_statement() {
    let expr = parse::<ast::Statement>("return [0:1];");
    assert_eq!(expr.ast, ast::Statement::Branch {
        dst: ast::BranchDst::Indirect(ast::JumpLabel::Integer(0, 1)),
        hint: ast::BranchHint::Return
    });
}

#[test]
fn complex_pcode_statement() {
    let _ = parse::<ast::Statement>("XmmReg1[0,8] = (XmmReg1[0,8] == XmmReg2[0,8]) * 0xFF;");
}

#[test]
fn macro_in_expr() {
    let _ = parse::<ast::Statement>(
        r#"
@define Carry "F[0,1]"
r = (r << 1) | $(Carry);"#,
    );
}

#[test]
fn mips() {
    let path = std::path::PathBuf::from(std::env::var_os("GHIDRA_SRC").unwrap())
        .join("Ghidra/Processors/MIPS/data/languages/mips32le.slaspec");

    let mut parser = Parser::from_path(path).unwrap();
    match parser.parse::<crate::ast::Sleigh>() {
        Ok(_) => {}
        Err(e) => {
            let dbg = format!("{:?}", e);
            eprintln!("{}", parser.error_formatter(e));
            panic!("{}", dbg);
        }
    }
}

#[test]
fn x86() {
    let path = std::path::PathBuf::from(std::env::var_os("GHIDRA_SRC").unwrap())
        .join("Ghidra/Processors/x86/data/languages/x86-64.slaspec");

    let mut parser = Parser::from_path(path).unwrap();
    match parser.parse::<crate::ast::Sleigh>() {
        Ok(_) => {}
        Err(e) => {
            let dbg = format!("{:?}", e);
            eprintln!("{}", parser.error_formatter(e));
            panic!("{}", dbg);
        }
    }
}

#[test]
fn msp430() {
    let path = std::path::PathBuf::from(std::env::var_os("GHIDRA_SRC").unwrap())
        .join("Ghidra/Processors/TI_MSP430/data/languages/TI_MSP430X.slaspec");

    let mut parser = Parser::from_path(path).unwrap();
    match parser.parse::<crate::ast::Sleigh>() {
        Ok(_) => {}
        Err(e) => {
            let dbg = format!("{:?}", e);
            eprintln!("{}", parser.error_formatter(e));
            panic!("{}", dbg);
        }
    }
}

#[test]
fn aarch64() {
    let path = std::path::PathBuf::from(std::env::var_os("GHIDRA_SRC").unwrap())
        .join("Ghidra/Processors/AARCH64/data/languages/AARCH64.slaspec");

    let mut parser = Parser::from_path(path).unwrap();
    match parser.parse::<crate::ast::Sleigh>() {
        Ok(_) => {}
        Err(e) => {
            let dbg = format!("{:?}", e);
            eprintln!("{}", parser.error_formatter(e));
            panic!("{}", dbg);
        }
    }
}

#[test]
fn armv7() {
    let path = std::path::PathBuf::from(std::env::var_os("GHIDRA_SRC").unwrap())
        .join("Ghidra/Processors/ARM/data/languages/ARM7_le.slaspec");

    let mut parser = Parser::from_path(path).unwrap();
    match parser.parse::<crate::ast::Sleigh>() {
        Ok(_) => {}
        Err(e) => {
            let dbg = format!("{:?}", e);
            eprintln!("{}", parser.error_formatter(e));
            panic!("{}", dbg);
        }
    }
}
