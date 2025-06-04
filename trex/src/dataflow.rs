//! Compute data flow across the [`il::Program`](crate::il::Program)

use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::il::{Op, Program};
use crate::log::*;
use std::collections::VecDeque;
use std::rc::Rc;

/// A pointer into some address space.
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct ASLocation {
    /// An index into the program's address spaces
    pub address_space_idx: usize,
    /// An offset into the address space
    pub offset: usize,
}
impl std::fmt::Debug for ASLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let ASLocation {
            address_space_idx,
            offset,
        } = self;
        write!(f, "ASLocation(as={}, off={:#x})", address_space_idx, offset)
    }
}

#[derive(PartialEq, PartialOrd, Ord, Eq, Clone, Copy, Hash)]
/// Different program points to refer to points in the program, as well as their predecessors and
/// successors.
pub enum ProgPoint {
    Insn(usize),
}
impl std::fmt::Debug for ProgPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProgPoint::Insn(n) => write!(f, "Insn({})", n),
        }
    }
}

/// A summary of the program, keeping track of inputs, outputs, predecessors, and successors of each
/// IL instruction in the program.
#[derive(Debug)]
pub struct ProgramSummary {
    pub predecessors: Vec<UnorderedSet<ProgPoint>>,
    pub successors: Vec<UnorderedSet<ProgPoint>>,
    pub fn_of_ilpc: Vec<usize>,
    pub start_of_fn: Vec<usize>,
    pub end_of_fn: Vec<usize>,
    pub outputs: Vec<Vec<Option<ASLocation>>>,
    pub inputs: Vec<Vec<Option<ASLocation>>>,
    pub all_variables_of_fn: Vec<UnorderedSet<ASLocation>>,
    // Keep a read-only copy of the program around, so as to guarantee program doesn't change
    // underneath us :)
    pub program: Rc<Program>,
}

impl ProgramSummary {
    /// Compute a summary of the `program`
    pub fn compute_from(program: &Rc<Program>) -> Rc<Self> {
        let l = program.instructions.len();
        let mut r = Self {
            predecessors: vec![Default::default(); l],
            successors: vec![Default::default(); l],
            fn_of_ilpc: vec![],
            start_of_fn: vec![],
            end_of_fn: vec![],
            outputs: vec![Default::default(); l],
            inputs: vec![Default::default(); l],
            all_variables_of_fn: vec![Default::default(); program.functions.len()],
            program: program.clone(),
        };

        fn no_overlaps_amongst_functions(program: &Rc<Program>) -> bool {
            let mut seen = vec![false; program.instructions.len()];
            for (_func_name, _unaffected, bbs, _entry) in &program.functions {
                for &bb in bbs {
                    for &ins in &program.basic_blocks[bb] {
                        if seen[ins] {
                            return false;
                        }
                        seen[ins] = true;
                    }
                }
            }
            true
        }

        assert!(
            no_overlaps_amongst_functions(program),
            "As a whole, data flow analysis and anything that uses it makes assumptions that \
             functions do not share code. If this assumption is ever \
             broken, then a non-trivial part of the analyses might need updates."
        );

        {
            let mut fnmap = vec![None; program.instructions.len()];
            let mut fnend = vec![None; program.functions.len()];
            let mut fnstart = vec![None; program.functions.len()];
            for (func_id, (_func_name, _unaffected, bbs, _entry)) in
                program.functions.iter().enumerate()
            {
                for &bb in bbs {
                    for &ins in &program.basic_blocks[bb] {
                        assert!(fnmap[ins].is_none());
                        fnmap[ins] = Some(func_id);
                        match program.instructions[ins].op {
                            Op::FunctionStart => {
                                assert!(fnstart[func_id].is_none());
                                fnstart[func_id] = Some(ins);
                            }
                            Op::FunctionEnd => {
                                assert!(fnend[func_id].is_none());
                                fnend[func_id] = Some(ins);
                            }
                            _ => {}
                        }
                    }
                }
            }
            r.fn_of_ilpc = fnmap
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    v.ok_or_else(|| {
                        format!(
                            "Instruction {}: `{:?}` found to have no function",
                            i, program.instructions[i]
                        )
                    })
                    .unwrap()
                })
                .collect();
            r.start_of_fn = fnstart.into_iter().map(Option::unwrap).collect();
            r.end_of_fn = fnend.into_iter().map(Option::unwrap).collect();
        };

        for i in 0..program.instructions.len() {
            let succs = program.get_successor_instruction_addresses_for(i);
            if !succs.is_empty() {
                for j in succs {
                    if r.fn_of_ilpc[j] == r.fn_of_ilpc[i] {
                        r.successors[i].insert(ProgPoint::Insn(j));
                        r.predecessors[j].insert(ProgPoint::Insn(i));
                    } else {
                        debug!(
                            "Found branch across functions, ignoring in success/predecessor calculation";
                            "fn_of_ilpc[j]" => &program.functions[r.fn_of_ilpc[j]].0,
                            "j" => j,
                            "fn_of_ilpc[i]" => &program.functions[r.fn_of_ilpc[i]].0,
                            "i" => i,
                        );
                    }
                }
            } else {
                let fnend = r.end_of_fn[r.fn_of_ilpc[i]];
                r.successors[i].insert(ProgPoint::Insn(fnend));
                r.predecessors[fnend].insert(ProgPoint::Insn(i));
            }

            r.outputs[i] = vec![];
            if program.instructions[i].output.is_used() {
                r.outputs[i].push(program.instructions[i].output.try_to_aslocation());
            }

            r.inputs[i] = vec![];
            for inp in &program.instructions[i].inputs {
                if inp.is_used() {
                    r.inputs[i].push(inp.try_to_aslocation());
                }
            }

            for &v in r.outputs[i].iter().chain(r.inputs[i].iter()) {
                if let Some(v) = v {
                    r.all_variables_of_fn[r.fn_of_ilpc[i]].insert(v);
                }
            }
        }

        Rc::new(r)
    }
}

/// A single element in the data-flow analysis. Each instruction in the IL program holds on to one
/// member of this element.
///
/// The definition of this element is crucial to defining the entire data flow, since it also
/// defines the expected transfer function for the data flow.
pub trait DataFlowElement: PartialEq + Clone {
    /// The initial/default value to start at.
    fn init() -> Self;
    /// The join operator, when joining outs from different predecessors.
    ///
    /// Satisfies property `a.join_from(init())` keeps `a` unmodified.
    fn join_from(&mut self, other: &Self);

    /// The initial/default value to start at, at function's start (with function starting at IL PC
    /// `fn_start`)
    // XXX: Given changes that introduced this comment (see commit) it might be possible to remove
    // this function entirely from the trait.
    fn init_func_start(summary: &ProgramSummary, fn_start: usize) -> Self;

    /// The transfer function that (along with the init and join) defines the specific kind of data
    /// flow analysis at play.
    fn transfer_function(&self, ins: usize, summary: &ProgramSummary) -> Self;
}

/// Resuls of a data flow analysis. Uses the definition of the [`DataFlowElement`] to define the
/// type of analysis.
#[derive(Debug)]
pub struct DataFlow<T: DataFlowElement> {
    pub outs: UnorderedMap<usize, T>,
    pub ins: UnorderedMap<usize, T>,
    pub summary: Rc<ProgramSummary>,
    // Keep a read-only copy of the program around, so as to guarantee program doesn't change
    // underneath us while we are using the results of the analysis :)
    program: Rc<Program>,
}

impl<T: DataFlowElement> DataFlow<T> {
    /// Perform a forwards analysis of the data flow of the `program`
    ///
    /// Uses the worklist algorithm to compute data flow
    pub fn forward_analyze(program_summary: &Rc<ProgramSummary>, func_id: usize) -> Self {
        let program = &program_summary.program;
        let func_il_addrs = program.functions[func_id]
            .2
            .iter()
            .flat_map(|&bbidx| program.basic_blocks[bbidx].iter())
            .cloned()
            .collect::<Vec<usize>>();

        let outs: UnorderedMap<usize, T> = func_il_addrs
            .iter()
            .cloned()
            .map(|il_addr| (il_addr, T::init()))
            .collect();
        let ins = outs.clone();

        let mut r = Self {
            outs,
            ins,
            summary: program_summary.clone(),
            program: program.clone(),
        };

        let func_il_addrs: UnorderedSet<usize> = func_il_addrs.into_iter().collect();
        let mut changed: VecDeque<usize> = func_il_addrs.iter().cloned().collect();

        while !changed.is_empty() {
            let n = changed.pop_front().unwrap();

            r.ins.insert(n, T::init());
            if r.summary.predecessors[n].is_empty() {
                let ins = &r.summary.program.instructions[n];
                let is_branch_to_self_right_after_a_ud2 = ins.op == Op::Branch
                    && match ins.inputs[0] {
                        crate::il::Variable::MachineAddress { addr } => addr == ins.address,
                        _ => false,
                    }
                    && r.summary.program.instructions[r
                        .summary
                        .program
                        .get_il_addrs_for_machine_addr(ins.address)
                        .unwrap()
                        .0]
                        .op
                        == Op::ProcessorException;
                if ins.op != Op::FunctionStart {
                    if !is_branch_to_self_right_after_a_ud2 {
                        debug!(
                            "Non-FunctionStart instruction found to not have predecessor";
                            "ilpc" => n,
                            "ins" => ?ins,
                        );
                    }
                }
                if !is_branch_to_self_right_after_a_ud2 {
                    r.ins
                        .get_mut(&n)
                        .unwrap()
                        .join_from(&T::init_func_start(&r.summary, n));
                }
            } else {
                if !r.summary.predecessors[n]
                    .iter()
                    .all(|ProgPoint::Insn(p)| func_il_addrs.contains(&p))
                {
                    panic!("Found predecessors outside the function");
                }
                for &p in &r.summary.predecessors[n] {
                    r.ins.get_mut(&n).unwrap().join_from(match p {
                        ProgPoint::Insn(p) => &r.outs.get(&p).unwrap(),
                    });
                }
            }

            let old_out = std::mem::replace::<T>(
                &mut r.outs.get_mut(&n).unwrap(),
                r.ins.get(&n).unwrap().transfer_function(n, &r.summary),
            );

            if *r.outs.get(&n).unwrap() != old_out {
                for &s in &r.summary.successors[n] {
                    match s {
                        ProgPoint::Insn(s) => changed.push_back(s),
                    }
                }
            }
        }

        r
    }
}
