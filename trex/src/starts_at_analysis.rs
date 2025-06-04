//! Analysis to figure out co-location behavior, in order to recover `struct` types.

use std::collections::VecDeque;
use std::rc::Rc;

use crate::constant_folding::ConstFolded;
use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::dataflow::ProgPoint;
use crate::il::Op;
use crate::log::*;
use crate::ssa::Variable;
use crate::structural::StructuralTypes;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Constraints discovered while trying to recover co-location
pub enum Constraint {
    /// A dereference from a fixed offset has been observed. For example, `x = *(y + 10)`
    OffsetDeref {
        /// The value being accessed. In the example, this is `x`.
        t: Variable,
        /// The offset from the base pointer. In the example, this is `10`.
        offset: i64,
        /// The base pointer being used. In the example, this is `y`.
        base_ptr: Variable,
    },
    /// An non-constant-offset dereference from a known pointer-type has been observed. For example,
    /// `x = *(y + z)`, where `y` is a pointer but `z` is not.
    NonConstantOffsetDeref {
        /// The value being accessed. In the example, this is `x`.
        t: Variable,
        /// The base pointer being used. In the example, this is `y`.
        base_ptr: Variable,
        /// The offset being used. In the example, this is `z`.
        offset: Variable,
    },
}

/// Discovered co-location constraints.
pub struct CoLocated {
    /// A map of constraints to instructions that imply this constraint.
    ///
    /// It is possible that many instructions might be needed to imply a constraint, or a bunch of
    /// different instructions _separately_ imply the constraint. We lump all of these together.
    pub constraints: UnorderedMap<Constraint, UnorderedSet<usize>>,
    /// The structural types from which the co-location constraints have been discovered.
    pub structural_types: Rc<StructuralTypes>,
    /// On-demand constant-folding
    constant_folding: Rc<ConstFolded>,
}

impl std::fmt::Debug for CoLocated {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("CoLocated")
            .field(
                "constraints",
                &self
                    .constraints
                    .iter()
                    .map(|(c, r)| (c, format!("reason: {:?}", r)))
                    .collect::<UnorderedMap<_, _>>(),
            )
            .finish_non_exhaustive()
    }
}

/// An internal structure to better organize worklist execution
struct WorklistElement {
    /// The instruction being analyzed
    il_pc: usize,
    /// The current base pointer
    ptr: Variable,
    /// The pointee
    val: Variable,
    /// List of IL instructions that led to this particular element being analyzed
    reason: Vec<usize>,
}

impl CoLocated {
    /// Analyze the given `structural_types` and recover co-location constraints
    pub fn analyze(structural_types: &Rc<StructuralTypes>) -> Self {
        let mut r = Self {
            constraints: Default::default(),
            structural_types: structural_types.clone(),
            constant_folding: ConstFolded::from_ssa(&structural_types.ssa),
        };

        // We use a `VecDeque` here rather than a `Vec` simply to make debugging a little more
        // understandable since it will then work like a queue rather than a stack. The order itself
        // should be irrelevant.
        let mut worklist: VecDeque<WorklistElement> = structural_types
            .ssa
            .program
            .instructions
            .iter()
            .enumerate()
            .flat_map(|(i, _ins)| r.initial_worklist_elements_at(i))
            .collect();

        // XXX: Is this sane? Will we miss anything by doing this?
        let mut seen: UnorderedMap<Variable, (UnorderedSet<usize>, UnorderedSet<usize>)> =
            Default::default();

        while let Some(args) = worklist.pop_front() {
            let mut seen_before = true;
            if !seen.contains_key(&args.val) {
                seen_before = false;
                seen.insert(args.val.clone(), Default::default());
            }
            let (pc, re) = seen.get_mut(&args.val).unwrap();
            if pc.insert(args.il_pc) {
                seen_before = false;
            }
            for &r in &args.reason {
                if re.insert(r) {
                    seen_before = false;
                    // Don't short-circuit stop here, because we want to still insert everything in
                }
            }
            if seen_before {
                continue;
            }

            r.analyze_instruction_at(args, &mut worklist);
        }

        r
    }

    /// Get the initial set of worklist elements for an instruction at `il_pc`
    fn initial_worklist_elements_at(
        &self,
        il_pc: usize,
    ) -> Box<dyn Iterator<Item = WorklistElement>> {
        let ssa = &self.structural_types.ssa;
        let ins = &ssa.program.instructions[il_pc];
        match ins.op {
            Op::Store => Box::new(std::iter::once(WorklistElement {
                il_pc,
                ptr: ssa.get_input_variable(il_pc, 0),
                val: ssa.get_input_variable(il_pc, 1),
                reason: vec![],
            })),
            Op::Load => {
                let ptr = ssa.get_input_variable(il_pc, 0);
                Box::new(
                    ssa.get_output_impacted_variable(il_pc)
                        .into_iter()
                        .map(move |val| WorklistElement {
                            il_pc,
                            ptr: ptr.clone(),
                            val,
                            reason: vec![],
                        }),
                )
            }
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Perform the requisite work on the element `wle`, adding any newly discovered elements to be
    /// analyzed into `worklist`.
    fn analyze_instruction_at(
        &mut self,
        wle: WorklistElement,
        worklist: &mut VecDeque<WorklistElement>,
    ) {
        let ssa = &self.structural_types.ssa;

        // Add the immediately obvious constraint, visible from the deref
        if matches!(ssa.program.instructions[wle.il_pc].op, Op::Load | Op::Store) {
            self.constraints
                .entry(Constraint::OffsetDeref {
                    t: wle.val.clone(),
                    offset: 0,
                    base_ptr: wle.ptr.clone(),
                })
                .or_default()
                .extend(wle.reason.iter().cloned().chain(std::iter::once(wle.il_pc)));
        }

        // Add constraints due to second-order effects
        for affecting_il_pc in ssa.get_all_immediately_affecting_instructions(wle.ptr.clone()) {
            let ins = &ssa.program.instructions[affecting_il_pc];
            // XXX: Should we also be looking into `IntAnd` and such? They might be used to align
            // things sometimes?
            match ins.op {
                Op::IntAdd | Op::IntSub => {
                    let m = match ins.op {
                        Op::IntAdd => 1,
                        Op::IntSub => -1,
                        _ => unreachable!(),
                    };
                    let (a, b) = (
                        ssa.get_input_variable(affecting_il_pc, 0),
                        ssa.get_input_variable(affecting_il_pc, 1),
                    );

                    let is_a_const = ssa.is_effectively_constant(a.clone());
                    let is_b_const = ssa.is_effectively_constant(b.clone());
                    let (constraint, new_wle_base_ptr) = match (is_a_const, is_b_const) {
                        (false, true) | (true, false) => {
                            // Only one side is a constant, this is likely a struct-like dereference
                            let c_posn = if is_a_const { 0 } else { 1 };
                            let c: i64 = if let Some(c) =
                                self.constant_folding.input_at(affecting_il_pc, c_posn)
                            {
                                c as i64
                            } else {
                                debug!(
                                    "Effectively-constant and constant-folding disagree. Ignoring.";
                                    "ins" => ?ins,
                                    "c_posn" => c_posn,
                                    "affecting_il_pc" => affecting_il_pc,
                                );
                                continue;
                            };
                            let basev = if is_a_const { b } else { a };

                            let baset = self.structural_types.get_type_of(&basev).unwrap();
                            if baset.pointer_to.is_some() {
                                // `basev` is a pointer
                                (
                                    Constraint::OffsetDeref {
                                        t: wle.val.clone(),
                                        offset: c * m,
                                        base_ptr: basev.clone(),
                                    },
                                    Some(basev),
                                )
                            } else {
                                // The constant is the pointer, and we have a non-constant
                                // dereference from it, meaning that there likely an array at that
                                // constant.
                                (
                                    Constraint::NonConstantOffsetDeref {
                                        t: wle.val.clone(),
                                        offset: basev,
                                        base_ptr: Variable::ConstantValue {
                                            value: c as u64,
                                            progpoint: ProgPoint::Insn(affecting_il_pc),
                                            input_posn_in_il_insn: c_posn,
                                        },
                                    },
                                    None,
                                )
                            }
                        }
                        (true, true) => {
                            let ca = self.constant_folding.input_at(affecting_il_pc, 0);
                            let cb = self.constant_folding.input_at(affecting_il_pc, 1);
                            info!(
                                "TODO: Both sides effectively constant, should be calculating constant here?";
                                "op" => ?ins.op,
                                "ilpc" => affecting_il_pc,
                                "const_a" => ca,
                                "const_b" => cb,
                            );
                            continue;
                        }
                        (false, false) => {
                            // Both sides are non-constant, we have an array-like dereference.
                            let a_t = self.structural_types.get_type_of(&a).unwrap();
                            let b_t = self.structural_types.get_type_of(&b).unwrap();

                            let (base_ptr, offset) = match (a_t.pointer_to, b_t.pointer_to) {
                                (Some(_), None) => (a, b),
                                (None, Some(_)) => (b, a),
                                (None, None) => {
                                    debug!(
                                        "Both non-pointer variables";
                                        "ilpc" => affecting_il_pc,
                                        "a" => ?a,
                                        "op" => ?ins.op,
                                        "b" => ?b,
                                    );
                                    continue;
                                }
                                (Some(_), Some(_)) => {
                                    debug!(
                                        "Both pointer variables";
                                        "ilpc" => affecting_il_pc,
                                        "a" => ?a,
                                        "op" => ?ins.op,
                                        "b" => ?b,
                                    );
                                    continue;
                                }
                            };

                            (
                                Constraint::NonConstantOffsetDeref {
                                    t: wle.val.clone(),
                                    offset,
                                    base_ptr: base_ptr.clone(),
                                },
                                Some(base_ptr),
                            )
                        }
                    };

                    self.constraints.entry(constraint).or_default().extend(
                        wle.reason
                            .iter()
                            .cloned()
                            .chain([wle.il_pc, affecting_il_pc]),
                    );
                    if let Some(ptr) = new_wle_base_ptr {
                        worklist.push_back(WorklistElement {
                            il_pc: affecting_il_pc,
                            ptr,
                            val: wle.val.clone(),
                            reason: wle.reason.iter().cloned().chain([wle.il_pc]).collect(),
                        });
                    }
                }
                _ => {} // do nothing
            }
        }
    }

    /// Get the base variables to discovered aggregate types.
    pub fn get_aggregate_base_variables(&self) -> Vec<Variable> {
        self.constraints
            .keys()
            .filter(|c| match c {
                Constraint::OffsetDeref { offset, .. } => *offset != 0,
                Constraint::NonConstantOffsetDeref { .. } => true,
            })
            .map(|c| match c {
                Constraint::OffsetDeref { base_ptr, .. } => base_ptr,
                Constraint::NonConstantOffsetDeref { base_ptr, .. } => base_ptr,
            })
            .cloned()
            // De-duplicate (and order them nicely, for human readability; an `UnorderedSet` _would_ work
            // btw, just wouldn't lead to a consistent order for quick-glance reading)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}
