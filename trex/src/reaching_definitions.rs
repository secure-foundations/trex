//! [`DataFlow`](crate::dataflow::DataFlow) equations for the reaching-definitions analysis.

use std::rc::Rc;

use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::dataflow::{ASLocation, DataFlowElement, ProgPoint, ProgramSummary};
use crate::il::Op;

#[derive(PartialEq, Clone)]
// PERF: This is going to be a quite inefficient representation. Might be good to use a `Cow` or
// similar to reduce the number of copies held around?
#[derive(Debug)]
/// Reaching definitions at a specific IL instruction.
pub struct ReachingDefinitionsElement {
    /// A map of locations to the set of definition points that reach it.
    pub defs: UnorderedMap<ASLocation, Rc<UnorderedSet<ProgPoint>>>,
}

impl DataFlowElement for ReachingDefinitionsElement {
    /// Initially, all reaching definitions start out empty.
    fn init() -> Self {
        // PERF: can optimize by OUT[n] = GEN[n];
        //
        // Would likely require having separate inits, as well as allowing access to the summary at
        // the point of initialization.
        Self {
            defs: Default::default(),
        }
    }

    /// Joining two reaching definitions consists of taking the union on all definitions.
    fn join_from(&mut self, other: &Self) {
        for (d, s) in other.defs.iter() {
            let def_d = self.defs.entry(*d).or_insert_with(Default::default);
            *def_d = Rc::new(def_d.union(s).cloned().collect());
        }
    }

    /// The initial/default value to start at, at function's start (with function starting at IL PC
    /// `fn_start`)
    fn init_func_start(summary: &ProgramSummary, fn_start: usize) -> Self {
        Self {
            defs: summary.all_variables_of_fn[summary.fn_of_ilpc[fn_start]]
                .iter()
                .map(|&v| {
                    (
                        v,
                        Rc::new(std::iter::once(ProgPoint::Insn(fn_start)).collect()),
                    )
                })
                .collect(),
        }
    }

    /// An instruction transfers reaching definitions by killing all over-ridden values in the
    /// output, replacing it with the current definition. All other definitions stay the same.
    fn transfer_function(&self, ins: usize, summary: &ProgramSummary) -> Self {
        // OUT[n] = GEN[n] Union (IN[n] -KILL[n]);
        let mut ret = self.clone();
        assert!(
            summary.outputs[ins].len() <= 1,
            "Currently, the reaching-definitions analysis assumes that each instruction has at \
             max one output. For some reason, this is not true: {:?}. Either that must be \
             fixed, or the whole reaching-definitions analysis needs to be re-checked to find \
             all required changes",
            &summary.outputs[ins]
        );

        // Check if we are at a call, performing necessary clobbering
        match summary.program.instructions[ins].op {
            Op::CallWithFallthroughIndirect => {
                // Can't be sure, just kill everything
                for (_asl, pp) in ret.defs.iter_mut() {
                    *pp = Rc::new(std::iter::once(ProgPoint::Insn(ins)).collect());
                }
            }
            Op::CallWithFallthrough => {
                // Look up the callee, and kill everything not in the callee's unaffected list.
                let mut affected: UnorderedSet<ASLocation> = ret.defs.keys().cloned().collect();

                let target = summary.program.instructions[ins].inputs[0].clone();
                for v in summary
                    .program
                    .get_unaffected_variables_for_call_to(target, ins)
                {
                    affected.remove(&v.try_to_aslocation().unwrap());
                }

                for (asl, pp) in ret.defs.iter_mut() {
                    if affected.contains(asl) {
                        *pp = Rc::new(std::iter::once(ProgPoint::Insn(ins)).collect());
                    }
                }
            }
            Op::CallWithNoFallthrough | Op::CallWithNoFallthroughIndirect => {
                // Nothing to do here for these calls, since there is no fallthrough anyways
            }
            _ => {
                // Not a call, do nothing
            }
        }

        for d in summary.outputs[ins].iter().flatten() {
            let def_d = ret.defs.entry(*d).or_insert_with(Default::default);
            *def_d = Rc::new(std::iter::once(ProgPoint::Insn(ins)).collect());
        }
        ret
    }
}
