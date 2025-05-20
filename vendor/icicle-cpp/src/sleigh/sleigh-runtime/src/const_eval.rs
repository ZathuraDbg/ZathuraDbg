/// A restricted form of constant evaluation used for disassembly time constants.
pub fn const_eval(dst: pcode::VarNode, op: pcode::Op, inputs: &pcode::Inputs) -> Option<u64> {
    let inputs = inputs.get();
    if dst.size > 8 || inputs[0].size() > 8 || inputs[1].size() > 8 {
        return None;
    }

    match (op, inputs) {
        (pcode::Op::ZeroExtend, [pcode::Value::Const(a, _), _]) => Some(a),
        (pcode::Op::SignExtend, [pcode::Value::Const(a, input_size), _]) => {
            let a = pcode::sxt64(a, input_size as u64 * 8);
            Some(a & pcode::mask(dst.size as u64 * 8))
        }
        (pcode::Op::IntAdd, [pcode::Value::Const(a, size), pcode::Value::Const(b, _)]) => {
            let a = pcode::sxt64(a, size as u64 * 8);
            let b = pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_add(b) & pcode::mask(size as u64 * 8))
        }
        (pcode::Op::IntSub, [pcode::Value::Const(a, size), pcode::Value::Const(b, _)]) => {
            let a = pcode::sxt64(a, size as u64 * 8);
            let b = pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_sub(b) & pcode::mask(size as u64 * 8))
        }
        (pcode::Op::IntRight, [pcode::Value::Const(a, size), pcode::Value::Const(b, _)]) => {
            if b >= size as u64 * 8 {
                return Some(0);
            }
            let a = pcode::sxt64(a, size as u64 * 8);
            Some((a >> b) & pcode::mask(size as u64 * 8))
        }
        (pcode::Op::IntLeft, [pcode::Value::Const(a, size), pcode::Value::Const(b, _)]) => {
            if b >= size as u64 * 8 {
                return Some(0);
            }
            Some((a << b) & pcode::mask(size as u64 * 8))
        }
        (pcode::Op::IntMul, [pcode::Value::Const(a, size), pcode::Value::Const(b, _)]) => {
            let a = pcode::sxt64(a, size as u64 * 8);
            let b = pcode::sxt64(b, size as u64 * 8);
            Some(a.wrapping_mul(b) & pcode::mask(size as u64 * 8))
        }
        (pcode::Op::IntAnd, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => Some(a & b),
        (pcode::Op::IntEqual, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => {
            Some(if a == b { 1 } else { 0 })
        }
        (pcode::Op::IntNotEqual, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => {
            Some(if a != b { 1 } else { 0 })
        }
        (pcode::Op::IntLess, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => {
            Some(if a < b { 1 } else { 0 })
        }
        (pcode::Op::IntLessEqual, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => {
            Some(if a <= b { 1 } else { 0 })
        }
        (pcode::Op::BoolAnd, [pcode::Value::Const(a, _), pcode::Value::Const(b, _)]) => {
            Some(if a != 0 && b != 0 { 1 } else { 0 })
        }
        (pcode::Op::BoolNot, [pcode::Value::Const(a, _), _]) => Some(if a == 0 { 1 } else { 0 }),
        (pcode::Op::IntNot, [pcode::Value::Const(a, size), _]) => {
            Some(!a & pcode::mask(size as u64 * 8))
        }
        // x OP 0 == 0 identities.
        (
            pcode::Op::BoolAnd | pcode::Op::IntAnd | pcode::Op::IntMul,
            [pcode::Value::Const(0, _), _] | [_, pcode::Value::Const(0, _)],
        ) => Some(0),

        _ => None,
    }
}
