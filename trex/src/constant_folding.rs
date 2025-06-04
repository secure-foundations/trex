//! On-demand constant folding; provides an API that looks like pre-computed constant folding, but
//! actually computes constant folding results only as necessary.

use std::cell::Cell;
use std::rc::Rc;

use crate::il::{self, Op};
use crate::log::*;
use crate::ssa::SSA;

/// A module-internal type to keep memoize constant folding results
enum Value {
    Unknown,
    SentinelForRecursion,
    Dynamic,
    Constant(u64),
}

/// The query-able constant folding analysis.
pub struct ConstFolded {
    /// The constants that have been seen until now for
    known_constants: Vec<[Cell<Value>; 2]>,
    ssa: Rc<SSA>,
}

impl ConstFolded {
    /// Construct a new query-able analysis.
    pub fn from_ssa(ssa: &Rc<SSA>) -> Rc<Self> {
        Rc::new(Self {
            known_constants: ssa
                .program
                .instructions
                .iter()
                .map(|_| [Cell::new(Value::Unknown), Cell::new(Value::Unknown)])
                .collect(),
            ssa: ssa.clone(),
        })
    }

    /// The constant output of the instruction at at `il_pc`, if it is a constant
    pub fn output_at(&self, il_pc: usize) -> Option<u64> {
        let ins = &self.ssa.program.instructions[il_pc];

        macro_rules! a {
            () => {
                self.input_at(il_pc, 0)?
            };
        }
        macro_rules! b {
            () => {
                self.input_at(il_pc, 1)?
            };
        }

        Some(match ins.op {
            Op::Copy => a!(),
            Op::IntAdd => a!() + b!(),
            Op::IntSub => a!() - b!(),
            Op::IntMult => a!() * b!(),
            Op::IntUDiv => a!() / b!(),
            Op::IntAnd => a!() & b!(),
            Op::IntOr => a!() | b!(),
            Op::IntZext => a!(),
            Op::IntLeftShift => a!() << b!(),
            Op::IntSext => match ins.inputs[0] {
                il::Variable::Varnode { size: 1, .. } => a!() as i8 as i64 as u64,
                il::Variable::Varnode { size: 2, .. } => a!() as i16 as i64 as u64,
                il::Variable::Varnode { size: 4, .. } => a!() as i32 as i64 as u64,
                _ => todo!(),
            },
            Op::SubPiece => {
                let v = a!() >> b!();
                match ins.output.try_size() {
                    Some(1) => v as u8 as u64,
                    Some(2) => v as u16 as u64,
                    Some(4) => v as u32 as u64,
                    Some(8) => v,
                    _ => todo!(),
                }
            }
            Op::Load
            | Op::Store
            | Op::Branch
            | Op::BranchIndOffset
            | Op::FunctionStart
            | Op::CallWithFallthrough
            | Op::CallWithFallthroughIndirect
            | Op::CallWithNoFallthrough
            | Op::CallWithNoFallthroughIndirect => {
                return None;
            }
            _ => {
                debug!("TODO: Constant folding unimplemented for"; "op" => ?ins.op);
                return None;
            }
        })
    }

    /// The constant input at `il_pc` at position `i` of the instruction, if it is a constant.
    pub fn input_at(&self, il_pc: usize, i: usize) -> Option<u64> {
        // Enter (potential) recursion, quit early if possible
        match self.known_constants[il_pc][i].replace(Value::Unknown) {
            Value::Unknown => {
                self.known_constants[il_pc][i].set(Value::SentinelForRecursion);
            }
            Value::SentinelForRecursion => {
                self.known_constants[il_pc][i].set(Value::Dynamic);
                return None;
            }
            Value::Dynamic => {
                self.known_constants[il_pc][i].set(Value::Dynamic);
                return None;
            }
            Value::Constant(c) => {
                self.known_constants[il_pc][i].set(Value::Constant(c));
                return Some(c);
            }
        }
        // Calculate the actual result
        let res = match &self.ssa.program.instructions[il_pc].inputs[i] {
            il::Variable::Constant { value, size: _ } => Some(*value),
            il::Variable::Varnode { .. } => {
                let v = self.ssa.get_input_variable(il_pc, i);
                let affecting_instructions: Vec<usize> = self
                    .ssa
                    .get_all_immediately_affecting_instructions(v)
                    .collect();
                match affecting_instructions.len() {
                    0 => unreachable!(),
                    1 => self.output_at(affecting_instructions[0]),
                    _ => None,
                }
            }
            _ => todo!(),
        };
        // Exiting (potential) recursion, values are now known
        self.known_constants[il_pc][i].set(match res {
            Some(c) => Value::Constant(c),
            None => Value::Dynamic,
        });
        // Return the result
        res
    }
}
