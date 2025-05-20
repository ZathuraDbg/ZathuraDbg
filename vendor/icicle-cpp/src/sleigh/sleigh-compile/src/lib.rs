use std::{collections::HashMap, path::Path};

use sleigh_parse::{ast, Parser};
use sleigh_runtime::{
    AttachmentIndex, Constructor, ConstructorDebugInfo, DecodeAction, DisplaySegment,
    NamedRegister, RegisterAlias, RegisterAttachment, SleighData, StrIndex,
};

pub use sleigh_parse::resolve_dependencies;

use crate::symbols::SymbolTable;

mod constructor;
mod matcher;
mod symbols;

#[cfg(feature = "ldefs")]
pub mod ldef;

#[cfg(feature = "ldefs")]
pub fn from_ldef_path(
    ldef_path: impl AsRef<Path>,
    id: &str,
    verbose: bool,
) -> Result<(SleighData, u64), ldef::Error> {
    let output = ldef::build(ldef_path.as_ref(), id, None, verbose)?;
    Ok((output.sleigh, output.initial_ctx))
}

pub fn from_path(sleigh_spec: impl AsRef<Path>) -> Result<SleighData, String> {
    build_inner(Parser::from_path(sleigh_spec.as_ref())?, false)
}

pub fn from_data(root: &str, data: HashMap<String, String>) -> Result<SleighData, String> {
    build_inner(Parser::from_input(root, data)?, false)
}

pub fn build_inner(mut parser: Parser, verbose: bool) -> Result<SleighData, String> {
    let ast = match parser.parse::<ast::Sleigh>() {
        Ok(ast) => ast,
        Err(e) => return Err(format!("{}", parser.error_formatter(e))),
    };

    let mut symbols = SymbolTable::new(parser);
    let mut ctx = Context {
        verbose,
        // @todo: make configurable
        capture_debug_info: true,
        ..Context::default()
    };
    ctx.data.alignment = 1;

    for item in ast.items {
        resolve_item(&mut ctx, &mut symbols, item)?;
    }

    ctx.data.default_space_size =
        symbols.default_space.map(|i| symbols.spaces[i as usize].size).unwrap_or(8);

    for entry in &symbols.context_fields {
        let name_str = symbols.parser.get_ident_str(entry.name);
        ctx.data.context_field_mapping.insert(name_str.to_owned(), ctx.data.context_fields.len());
        ctx.data
            .context_fields
            .push(sleigh_runtime::ContextField { field: entry.field, flow: entry.flow });
    }

    for constructor in &symbols.constructors {
        add_constructor(constructor, &mut ctx, &symbols);
    }

    // Add a dummy constructor used for error values
    let invalid_str = ctx.add_string("INVALID");
    ctx.data.constructors.push(Constructor {
        table: 0,
        mnemonic: Some(invalid_str),
        fields: (0, 0),
        decode_actions: (0, 0),
        post_decode_actions: (0, 0),
        subtables: 0,
        display: (0, 0),
        semantics: (0, 0),
        delay_slot: false,
        export: None,
        temporaries: (0, 0),
        num_labels: 0,
    });
    if ctx.capture_debug_info {
        ctx.data.debug_info.constructors.push(ConstructorDebugInfo { line: "invalid".into() });
    }

    for table in &symbols.tables {
        let matcher = matcher::build_sequential_matcher(&symbols, table, &ctx)?;
        ctx.data.matchers.push(matcher);
        if ctx.capture_debug_info {
            let name_str = symbols.parser.get_ident_str(table.name);
            let name = ctx.add_string(name_str);
            ctx.data.debug_info.subtable_names.push(name);
        }
    }

    ctx.data.named_registers = vec![NamedRegister::default(); symbols.registers.len()];

    // Reserve register 0 to use for invalid varnodes.
    let invalid = ctx.add_string("INVALID_VARNODE");
    ctx.data.registers.push(sleigh_runtime::RegisterInfo {
        name: invalid,
        size: 0,
        offset: u32::MAX,
        aliases: vec![],
    });

    // Map overlapping varnodes.
    let mut registers: Vec<_> = symbols.registers.into_iter().enumerate().collect();
    registers.sort_by_key(|(_, reg)| (std::cmp::Reverse(reg.size), reg.offset));
    for (idx, reg) in registers {
        let name_str = symbols.parser.get_ident_str(reg.name);
        ctx.data.register_name_mapping.insert(name_str.to_string(), idx as u32);

        let mut name = ctx.add_string(name_str);

        // Check if there is an existing mapping for this register, if so add it as an alias.
        if let Some((parent_idx, mut local_offset)) = ctx.data.register_mapping.get(&reg.offset) {
            let parent_reg = &ctx.data.named_registers[*parent_idx as usize];

            // Fix offsets for big-endian registers.
            let mut offset = reg.offset;
            if ctx.data.big_endian {
                local_offset = parent_reg.var.size - local_offset - reg.size as u8;
                offset = parent_reg.offset + local_offset as u32;
            }

            // Map varnodes refering to the current register to the subslice of the parent register
            // that this register overlaps.
            let var = parent_reg
                .get_var(local_offset, reg.size as u8)
                .ok_or_else(|| format!("Internal error: {name_str} crosses 128-bit boundary"))?;
            ctx.data.named_registers[idx] = NamedRegister { name, var, offset };

            // Add the current register as an alias in the parent register (used for the display
            // implementation)
            ctx.data.registers[var.id as usize].aliases.push(RegisterAlias {
                offset: var.offset as u16,
                size: reg.size,
                name,
            });
            continue;
        }

        // Note: `reg.size` can be larger than 128 bits which is larger than the emulator supports
        // we handle this by creating new registers for each 128-bit slice (see below) and fix up
        // the IDs when extracting subslices (see: NamedRegister::get_var).
        let reg_id = ctx.data.registers.len().try_into().unwrap();
        ctx.data.named_registers[idx] = NamedRegister {
            name,
            var: pcode::VarNode::new(reg_id, reg.size as u8),
            offset: reg.offset,
        };

        // Map all the bytes within this range to the register.
        for byte in 0..reg.size {
            let varnode_offset = reg.offset + byte as u32;
            ctx.data.register_mapping.insert(varnode_offset, (idx as u32, byte as u8));
        }

        // We only support operating on registers that are at most 128-bits. This is only an issue
        // when dealing with vector operations (e.g. AVX, NEON). To handle this we need to split the
        // register into multiple smaller registers.
        for i in (0..reg.size).step_by(16) {
            let size = std::cmp::min(reg.size - i, 16) as u8;

            if i != 0 {
                name = ctx.add_string(&format!("{}_{}", name_str, i));
            }

            ctx.data.registers.push(sleigh_runtime::RegisterInfo {
                name,
                size,
                offset: reg.offset + i as u32,
                aliases: vec![],
            });
        }
    }

    // Register additional varnodes for saved temporaries
    for i in 0..8 {
        let var = ctx
            .data
            .add_custom_reg(&format!("$tmp{i}"), 16)
            .ok_or_else(|| format!("failed to reserve varnode for temporary"))?;
        ctx.data.saved_tmps.push(var);
    }

    for attachment in &symbols.attachments {
        match attachment {
            symbols::Attachment::Register(regs, size) => {
                let start = ctx.data.attached_registers.len() as u32;
                for &entry in regs {
                    let reg = entry.map(|id| {
                        let reg = &ctx.data.named_registers[id as usize];
                        RegisterAttachment { name: reg.name, offset: reg.offset }
                    });
                    ctx.data.attached_registers.push(reg);
                }
                let end = ctx.data.attached_registers.len() as u32;

                let size = size.unwrap_or(ctx.data.default_space_size);
                ctx.data.attachments.push(AttachmentIndex::Register((start, end), size));
            }
            symbols::Attachment::Name(names) => {
                let start = ctx.data.attached_names.len() as u32;
                for name in names {
                    let (start, end) = ctx.add_string(name);
                    ctx.data.attached_names.push((start, end));
                }
                let end = ctx.data.attached_names.len() as u32;
                ctx.data.attachments.push(AttachmentIndex::Name((start, end)));
            }
            symbols::Attachment::Value(values) => {
                let start = ctx.data.attached_values.len() as u32;
                ctx.data.attached_values.extend(values.iter().map(|v| *v as i64));
                let end = ctx.data.attached_values.len() as u32;
                ctx.data.attachments.push(AttachmentIndex::Value((start, end)));
            }
        }
    }

    for userop in &symbols.user_ops {
        let (start, end) = ctx.add_string(symbols.parser.get_ident_str(*userop));
        ctx.data.user_ops.push((start, end));
    }

    Ok(ctx.data)
}

#[derive(Default)]
pub(crate) struct Context {
    data: SleighData,
    cache: SleighDataCache,

    has_endian: bool,
    has_alignment: bool,
    has_register_space: bool,
    has_ram_space: bool,

    verbose: bool,
    capture_debug_info: bool,
    with: Vec<ast::WithDef>,
}

impl Context {
    pub fn add_string(&mut self, s: &str) -> StrIndex {
        self.cache.add_string(s, &mut self.data)
    }
}

fn resolve_item(ctx: &mut Context, syms: &mut SymbolTable, item: ast::Item) -> Result<(), String> {
    // Macro for checking and returning error if a field has already been defined
    macro_rules! check_not_defined {
        ($field:expr, $msg:expr) => {{
            if $field {
                return Err($msg.into());
            }
            $field = true;
        }};
    }

    match item {
        ast::Item::DefineEndian(kind) => {
            check_not_defined!(ctx.has_endian, "duplicate endian definition");
            ctx.data.big_endian = kind == ast::EndianKind::Big;
            syms.endianness = kind;
        }
        ast::Item::DefineAlignment(bytes) => {
            check_not_defined!(ctx.has_alignment, "duplicate alignment definition");
            ctx.data.alignment = bytes.try_into().map_err(|_| "alignment too large")?;
        }
        ast::Item::DefineSpace(space) => {
            match space.kind {
                ast::SpaceKind::RegisterSpace => {
                    if space.default {
                        return Err("Register space cannot be used as the default space".into());
                    }
                    if space.word_size.is_some() {
                        return Err("Register space cannot have a word size".into());
                    }
                    check_not_defined!(
                        ctx.has_register_space,
                        "multiple register spaces not supported"
                    );

                    // Size is the only parameter that can change for register spaces (and I'm not
                    // currently sure what they do)
                    syms.define_space(space)?;
                }

                ast::SpaceKind::RamSpace => {
                    check_not_defined!(ctx.has_ram_space, "multiple ram spaces not supported");
                    syms.define_space(space)?;
                }
                ast::SpaceKind::RomSpace => return Err("rom space not implemented".into()),
            };
        }
        ast::Item::SpaceNameDef(def) => syms.define_register_names(def)?,
        ast::Item::DefineBitRange(entries) => {
            for entry in entries {
                syms.define_bitrange(entry)?;
            }
        }
        ast::Item::DefineContext(def) => syms.define_context(def)?,
        ast::Item::DefineToken(def) => syms.define_token(def)?,
        ast::Item::DefineUserOp(op) => syms.define_userop(op)?,
        ast::Item::AttachVariables(attach) => syms.attach_variables(attach)?,
        ast::Item::AttachNames(attach) => {
            syms.define_attachment(symbols::Attachment::Name(attach.names), &attach.fields)?
        }
        ast::Item::AttachValues(attach) => {
            syms.define_attachment(symbols::Attachment::Value(attach.values), &attach.fields)?
        }
        ast::Item::Macro(def) => syms.define_macro(def)?,
        ast::Item::Constructor(mut constructor) => {
            for with in ctx.with.iter().rev() {
                constructor.table = match (with.table, constructor.table) {
                    (Some(with), Some(constructor)) => {
                        let name = format!(
                            "{}{}",
                            syms.parser.get_ident_str(with),
                            syms.parser.get_ident_str(constructor)
                        );
                        Some(syms.parser.get_ident(&name))
                    }
                    (Some(with), None) => Some(with),
                    (None, constructor) => constructor,
                };

                if !with.disasm_actions.is_empty() {
                    constructor.disasm_actions = with
                        .disasm_actions
                        .iter()
                        .cloned()
                        .chain(constructor.disasm_actions.into_iter())
                        .collect();
                }

                constructor.constraint = ast::ConstraintExpr::Op(
                    Box::new(with.constraint.clone()),
                    ast::ConstraintOp::And,
                    Box::new(constructor.constraint),
                );
            }

            if let Err(e) = syms.define_constructor(ctx, &constructor) {
                if ctx.verbose {
                    eprintln!("[WARNING] {}", e);
                }
            }
        }
        ast::Item::With(mut def) => {
            let items = std::mem::take(&mut def.items);
            ctx.with.push(def);
            for item in items {
                resolve_item(ctx, syms, item)?;
            }
            ctx.with.pop();
        }
    }

    Ok(())
}

fn add_constructor(
    constructor: &constructor::Constructor,
    ctx: &mut Context,
    symbols: &SymbolTable,
) {
    let mut mnemonic = None;
    if let Some(value) = constructor.mnemonic.as_ref() {
        mnemonic = Some(ctx.cache.add_string(value, &mut ctx.data));
    }

    let fields_start = ctx.data.fields.len() as u32;
    for field in &constructor.fields {
        ctx.data.fields.push(*field);
    }
    let fields_end = ctx.data.fields.len() as u32;

    let decode_actions_start = ctx.data.decode_actions.len() as u32;
    for (field, expr) in &constructor.disasm_actions.context_mod {
        let start = ctx.data.context_disasm_expr.len() as u32;
        ctx.data.context_disasm_expr.extend_from_slice(expr);
        let end = ctx.data.context_disasm_expr.len() as u32;
        ctx.data.decode_actions.push(DecodeAction::ModifyContext(*field, (start, end)));
    }

    for field in &constructor.disasm_actions.global_set {
        let field = symbols.context_fields[*field as usize].field;
        ctx.data.decode_actions.push(DecodeAction::SaveContext(field));
    }

    for action in &constructor.decode_actions {
        ctx.data.decode_actions.push(action.clone());
    }
    let decode_actions_end = ctx.data.decode_actions.len() as u32;

    let post_decode_actions_start = ctx.data.post_decode_actions.len() as u32;
    for (field, expr) in &constructor.disasm_actions.fields {
        let start = ctx.data.disasm_exprs.len() as u32;
        ctx.data.disasm_exprs.extend_from_slice(expr);
        let end = ctx.data.disasm_exprs.len() as u32;
        ctx.data.post_decode_actions.push((*field, (start, end)));
    }
    let post_decode_actions_end = ctx.data.post_decode_actions.len() as u32;

    let semantics_start = ctx.data.semantics.len() as u32;
    for action in &constructor.semantics.actions {
        // @todo?: experiment to determine whether it is worth deduplicating the actions (I think
        // this is unlikely).
        ctx.data.semantics.push(action.clone());
    }
    let semantics_end = ctx.data.semantics.len() as u32;

    let temp_start = ctx.data.temporaries.len() as u32;
    for temp in &constructor.semantics.temporaries {
        ctx.data.temporaries.push(temp.clone());
    }
    let temp_end = ctx.data.temporaries.len() as u32;

    ctx.data.constructors.push(Constructor {
        table: constructor.table,
        mnemonic,
        fields: (fields_start, fields_end),
        decode_actions: (decode_actions_start, decode_actions_end),
        post_decode_actions: (post_decode_actions_start, post_decode_actions_end),
        subtables: constructor.subtables.len() as u32,
        display: constructor.display,
        semantics: (semantics_start, semantics_end),
        delay_slot: constructor.has_delay_slot(),
        export: constructor.semantics.export,
        temporaries: (temp_start, temp_end),
        num_labels: constructor.semantics.count_labels(),
    });

    if ctx.capture_debug_info {
        let info = ConstructorDebugInfo { line: symbols.format_span(&constructor.span) };
        ctx.data.debug_info.constructors.push(info);
    }
}

#[derive(Default)]
pub(crate) struct SleighDataCache {
    pub strings_map: HashMap<String, StrIndex>,
    pub display_map: HashMap<Vec<DisplaySegment>, (u32, u32)>,
}

impl SleighDataCache {
    fn add_string(&mut self, string: &str, data: &mut SleighData) -> StrIndex {
        if let Some(index) = self.strings_map.get(string) {
            return *index;
        }

        let index = data.add_string(string);
        self.strings_map.insert(string.to_owned(), index);
        index
    }

    fn add_display_segment(
        &mut self,
        segment: &[DisplaySegment],
        data: &mut SleighData,
    ) -> (u32, u32) {
        if let Some(index) = self.display_map.get(segment) {
            return *index;
        }

        let (start, end) = data.add_display_segments(segment);
        self.display_map.insert(segment.to_vec(), (start, end));
        (start, end)
    }
}

#[test]
fn backtrack_with_offset() {
    // https://github.com/icicle-emu/icicle-emu/pull/8#issuecomment-1527557130
    static TEST_SPEC: &str = r#"
    define endian=big;
    define alignment=1;

    define space ram type=ram_space size=4 default;
    define space register type=register_space size=4;

    define token t1(8)
        tf1=(0,7);

    sub_table: "sub_table a" is tf1=0 unimpl
    sub_table: "sub_table b" is tf1=2 unimpl

    :instr "a and" sub_table is tf1=1; sub_table  unimpl
    :instr "b" tf1           is tf1=1; tf1        unimpl"#;

    let sleigh = build_inner(sleigh_parse::Parser::from_str(TEST_SPEC), true).unwrap();
    let mut runtime = sleigh_runtime::Runtime::new(0);

    let inst = match runtime.decode(&sleigh, 0x0, &[0x01, 0x01]) {
        Some(inst) => inst,
        None => {
            panic!("Error decoding instruction: {:#?}", runtime.get_instruction().root(&sleigh))
        }
    };
    assert_eq!(inst.inst_start, 0);
    assert_eq!(inst.inst_next, 2);

    let disasm = runtime.disasm(&sleigh).expect("failed to disassembly instruction");
    assert_eq!(disasm, "instr b 0x1");
}
