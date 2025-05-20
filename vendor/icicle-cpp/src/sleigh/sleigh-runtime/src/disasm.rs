use std::fmt::Write;

use crate::{decoder::SubtableCtx, AttachmentRef, DisplaySegment, Field, SleighData};

pub fn disasm_subtable(ctx: SubtableCtx, disasm: &mut String) -> Option<()> {
    for segment in ctx.display_segments() {
        match segment {
            DisplaySegment::Literal(idx) => disasm.push_str(ctx.data.get_str(*idx)),
            DisplaySegment::Field(idx) => {
                let field = ctx.fields()[*idx as usize];
                let value = ctx.locals()[*idx as usize];
                disasm_field(ctx.data, value, field, disasm)?;
            }
            DisplaySegment::Subtable(idx) => {
                let ctx = ctx.visit_constructor(ctx.subtables()[*idx as usize]);
                disasm_subtable(ctx, disasm)?;
            }
        }
    }
    Some(())
}

/// Write the string representation of a field with a value to `disasm`.
fn disasm_field(sleigh: &SleighData, value: i64, field: Field, disasm: &mut String) -> Option<()> {
    let attachment = match field.attached {
        Some(id) => sleigh.get_attachment(id),
        None => {
            write_numeric_field(sleigh, value, field, disasm);
            return Some(());
        }
    };

    let idx = value as usize;
    match attachment {
        AttachmentRef::Name(names) => {
            disasm.push_str(sleigh.get_str(*names.get(idx)?));
        }
        AttachmentRef::Value(values) => {
            write_numeric_field(sleigh, *values.get(idx)?, field, disasm);
        }
        AttachmentRef::Register(regs, _) => {
            let name = (*regs.get(idx)?)?.name;
            disasm.push_str(sleigh.get_str(name));
        }
    }

    Some(())
}

/// Write the string representation of a numeric field with a value to `disasm`.
fn write_numeric_field(sleigh: &SleighData, value: i64, field: Field, disasm: &mut String) {
    // To match Ghidra's output we assume all numbers that are equal to the default
    // space size are also treated as signed.
    let is_signed = field.signed || (sleigh.default_space_size * 8 == field.num_bits);

    let fmt = pcode::NumericFormatter {
        value: value as u64,
        is_signed,
        is_hex: field.hex,
        num_bits: field.num_bits,
    };
    write!(disasm, "{}", fmt).unwrap();
}
