//! A global-value-numbering analysis. Computes congruence of different SSA [`Variable`]s.
//!
//! Using the congruence of variables, along with a dominator tree can allow an analysis to check if
//! two values are equal at a certain program point.
//!
//! Note that two congruent values must have the same type, even though their values have "not yet"
//! become the same, since the type of a variable is a static property, while the value itself is a
//! dynamic property. Thus, for type reconstruction, congruence already provides useful constraints.

use crate::containers::unordered::UnorderedSet;
use crate::containers::DisjointSet;
use crate::il::Op;
use crate::ssa::{Variable, SSA};
use std::rc::Rc;

/// The result of a global value numbering analysis
pub struct GlobalValueNumbering {
    /// The SSA IR upon which the analysis was done
    ssa: Rc<SSA>,
    /// Congruence relations discovered through analysis
    congruent: DisjointSet<Value>,
}

impl GlobalValueNumbering {
    /// Analyze `ssa` for global value numbering
    pub fn analyze_from(ssa: &Rc<SSA>) -> Self {
        let mut r = Self {
            ssa: ssa.clone(),
            congruent: DisjointSet::new(),
        };

        for (il_pc, ins) in ssa.program.instructions.iter().enumerate() {
            let op = ins.op;
            match OpSummary::of(op) {
                HasNoOutput | MustNotMerge | MightBeMergedInFutureButDoNotMergeNow => {}
                MergeCopy => r.congruent.merge(
                    Var(ssa.get_output_variable(il_pc)),
                    Var(ssa
                        .get_input_variable(il_pc, 0)
                        .normalize_program_point_for_const(&ssa.program)),
                ),
                MergeResultSingleArgument => r.congruent.merge(
                    Var(ssa.get_output_variable(il_pc)),
                    Op1(
                        op,
                        ssa.get_input_variable(il_pc, 0)
                            .normalize_program_point_for_const(&ssa.program),
                    ),
                ),
                MergeResultButNoCommutativity => r.congruent.merge(
                    Var(ssa.get_output_variable(il_pc)),
                    Op2(
                        op,
                        ssa.get_input_variable(il_pc, 0)
                            .normalize_program_point_for_const(&ssa.program),
                        ssa.get_input_variable(il_pc, 1)
                            .normalize_program_point_for_const(&ssa.program),
                    ),
                ),
                MergeResultWithCommutativity => {
                    let a = ssa
                        .get_input_variable(il_pc, 0)
                        .normalize_program_point_for_const(&ssa.program);
                    let b = ssa
                        .get_input_variable(il_pc, 1)
                        .normalize_program_point_for_const(&ssa.program);
                    r.congruent.merge(
                        Var(ssa.get_output_variable(il_pc)),
                        if a <= b { Op2(op, a, b) } else { Op2(op, b, a) },
                    );
                }
            }
        }

        r
    }

    /// Produce an iterator over the discovered sets of congruent variables
    pub fn congruent_sets_iter(&self) -> impl IntoIterator<Item = UnorderedSet<Variable>> {
        self.congruent
            .disjoint_sets_iter()
            .into_iter()
            .map(|m| {
                m.into_iter()
                    .filter_map(|v| {
                        if let Var(v) = v {
                            Some(v.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<UnorderedSet<Variable>>()
            })
            .filter(|m| m.len() >= 2)
            .collect::<Vec<_>>()
    }
}

/// A value node, used to refer to a computation of values
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Value {
    Var(Variable),
    Op1(Op, Variable),
    Op2(Op, Variable, Variable),
}
use Value::*;

/// A high-level summary of how to perform value numbering given a particular operator
enum OpSummary {
    HasNoOutput,
    MustNotMerge,
    MightBeMergedInFutureButDoNotMergeNow,
    MergeResultButNoCommutativity,
    MergeResultWithCommutativity,
    MergeCopy,
    MergeResultSingleArgument,
}
use OpSummary::*;

impl OpSummary {
    fn of(op: Op) -> Self {
        match op {
            Op::Branch
            | Op::CallWithFallthrough
            | Op::CallWithNoFallthrough
            | Op::BranchIndOffset
            | Op::Return
            | Op::CallWithFallthroughIndirect
            | Op::CallWithNoFallthroughIndirect
            | Op::Cbranch
            | Op::Store
            | Op::FunctionStart
            | Op::FunctionEnd
            | Op::Nop
            | Op::UnderspecifiedNoOutput
            | Op::ProcessorException => HasNoOutput,

            Op::UnderspecifiedOutputModification => MustNotMerge,

            Op::Copy => MergeCopy,

            Op::BoolNegate | Op::IntOnesComp | Op::IntTwosComp | Op::Popcount => {
                MergeResultSingleArgument
            }

            Op::FloatIsNan
            | Op::FloatAdd
            | Op::FloatSub
            | Op::FloatMult
            | Op::FloatDiv
            | Op::Float2Float => MightBeMergedInFutureButDoNotMergeNow,

            Op::Int2Float | Op::Float2IntTrunc => MergeResultSingleArgument,

            Op::FloatRound | Op::FloatNeg | Op::FloatAbs | Op::FloatSqrt => {
                MergeResultSingleArgument
            }

            Op::IntAdd
            | Op::IntMult
            | Op::IntAnd
            | Op::IntOr
            | Op::IntXor
            | Op::BoolAnd
            | Op::BoolOr
            | Op::BoolXor
            | Op::IntEqual
            | Op::IntNotEqual
            | Op::IntCarry
            | Op::IntSCarry
            | Op::FloatEqual
            | Op::FloatNotEqual => MergeResultWithCommutativity,

            Op::IntSub
            | Op::IntUDiv
            | Op::IntURem
            | Op::IntSDiv
            | Op::IntSRem
            | Op::IntSBorrow
            | Op::IntSLess
            | Op::IntLess
            | Op::FloatLess
            | Op::FloatLessEqual
            | Op::IntLeftShift
            | Op::IntURightShift
            | Op::IntSRightShift => MergeResultButNoCommutativity,

            Op::Load => MustNotMerge,

            Op::IntZext | Op::IntSext | Op::Piece | Op::SubPiece => {
                MightBeMergedInFutureButDoNotMergeNow
            }

            Op::ScalarLowerOp(_, _) | Op::ScalarUpperOp(_, _) | Op::PackedVectorOp(_, _) => {
                MightBeMergedInFutureButDoNotMergeNow
            }
        }
    }
}
