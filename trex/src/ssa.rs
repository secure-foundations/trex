//! Compute an SSA form of the [`il::Program`](crate::il::Program)
//!
//! The algorithm used to compute SSA is inspired by (but does not actually follow too closely):
//!
//! > Aycock J., Horspool N. (2000) Simple Generation of Static Single-Assignment Form. In: Watt
//! > D.A. (eds) Compiler Construction. CC 2000. Lecture Notes in Computer Science, vol
//! > 1781. Springer, Berlin, Heidelberg. <https://doi.org/10.1007/3-540-46423-9_8>
//!
//! In particular, here we choose to move some of the operations "up front" by using a
//! reaching-definitions analysis, and folding away "obvious" optimizations early. This also means
//! that we do not need to actually compute dominators or dominator frontiers (as would be needed by
//! an SSA algorithm like by Cytron), nor do we need to perform the eliminations needed in the above
//! paper, since such superfluous phi nodes never even show up.

use crate::containers::unordered::UnorderedSet;
use crate::containers::InsertionOrderedSet;
use crate::dataflow::{ASLocation, DataFlow, ProgPoint, ProgramSummary};
use crate::il::{self, Op, Program};
use crate::inference_config::CONFIG;
use crate::log::*;
use crate::reaching_definitions::ReachingDefinitionsElement;
use std::collections::VecDeque;
use std::rc::Rc;

/// An SSA variable, or a constant. We consider both together here to unify the way we reason about
/// them in the rest of the codebase.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum Variable {
    /// An actual SSA variable
    Variable { var: SSAVariable },
    /// A constant value. This is used to simplify constraint generation and type recovery in the
    /// presence of instructions containing IL-level constants, also referred to as "IL constant
    /// variables".
    ConstantValue {
        progpoint: ProgPoint,
        input_posn_in_il_insn: usize,
        value: u64,
    },
    /// A value-irrelevant constant, referring to things like program addresses. Its value is
    /// irrelevant and it doesn't carry any (useful) type information in later stages too. It exists
    /// solely to simplify code by unifying usage.
    ValueIrrelevantConstant,
}

impl std::fmt::Debug for Variable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Variable::Variable { var } => write!(f, "{:?}", var)?,
            Variable::ConstantValue {
                progpoint,
                value,
                input_posn_in_il_insn: posn,
            } => write!(
                f,
                "const(v={:#x}, prog_point={}, posn={})",
                value,
                match progpoint {
                    ProgPoint::Insn(i) => i,
                },
                posn,
            )?,
            Variable::ValueIrrelevantConstant => write!(f, "ValIrrelConst")?,
        }

        Ok(())
    }
}

/// An SSA variable. Is essentially just an identifier. Its internal meaning is captured by its
/// respective `SSAVarDefinition`, but accessing any information about it should be done through the
/// full [`SSA`] object.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SSAVariable(usize);

impl From<SSAVariable> for Variable {
    fn from(v: SSAVariable) -> Self {
        Self::Variable { var: v }
    }
}
impl From<&SSAVariable> for Variable {
    fn from(v: &SSAVariable) -> Self {
        Self::Variable { var: *v }
    }
}

impl std::fmt::Debug for SSAVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}
impl std::fmt::Display for SSAVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// An [`SSAVariable`]'s contents in the program.
#[derive(Debug, PartialEq, Eq, Clone)]
enum SSAVarDefinition {
    /// The SSA variable is defined as a phi-node.
    ///
    /// The set of arguments to a phi-node is an unordered set, that is usually taken as an ordered
    /// list of arguments due to notational convenience. We instead directly use a set
    /// representation to better model its intention.
    PhiNode(UnorderedSet<SSAVariable>),
    /// The SSA variable is defined as the result of the instruction at a particular IL address.
    ///
    /// We also hold on to the respective ASLocation since some instructions can produce multiple
    /// outputs (eg: Call instructions; function start is handled via `ValueAtFunctionStart`, but
    /// might be a good idea to coalesce that with this at some point).
    ILInstruction(usize, ASLocation),
    /// A variable generated at the start of the function (implying it is an argument to the
    /// function) with the given IL address start.
    ValueAtFunctionStart(usize, ASLocation),
}

impl std::hash::Hash for SSAVarDefinition {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        match self {
            SSAVarDefinition::PhiNode(vs) => {
                (0u8).hash(h);
                // use `sum` here so that it is an associative-commutative reduction over the
                // different `vs`
                vs.iter().map(|SSAVariable(v)| v).sum::<usize>().hash(h);
            }
            SSAVarDefinition::ILInstruction(i, asloc) => {
                (1u8).hash(h);
                i.hash(h);
                asloc.hash(h);
            }
            SSAVarDefinition::ValueAtFunctionStart(start, asloc) => {
                (2u8).hash(h);
                start.hash(h);
                asloc.hash(h);
            }
        }
    }
}
impl std::cmp::PartialOrd for SSAVarDefinition {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        fn t(s: &SSAVarDefinition) -> u8 {
            match s {
                SSAVarDefinition::PhiNode(_) => 0,
                SSAVarDefinition::ILInstruction(_, _) => 1,
                SSAVarDefinition::ValueAtFunctionStart(_, _) => 2,
            }
        }
        Some(t(self).cmp(&t(other)).then_with(|| match (self, other) {
            (SSAVarDefinition::PhiNode(vs1), SSAVarDefinition::PhiNode(vs2)) => {
                vs1.len().cmp(&vs2.len()).then_with(|| {
                    vs1.iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .cmp(&vs2.iter().collect::<std::collections::BTreeSet<_>>())
                })
            }
            (
                SSAVarDefinition::ILInstruction(i1, asloc1),
                SSAVarDefinition::ILInstruction(i2, asloc2),
            ) => i1.cmp(i2).then(asloc1.cmp(asloc2)),
            (
                SSAVarDefinition::ValueAtFunctionStart(start1, asloc1),
                SSAVarDefinition::ValueAtFunctionStart(start2, asloc2),
            ) => start1.cmp(start2).then(asloc1.cmp(asloc2)),
            _ => unreachable!("`t(..)` ensures both are of same variant"),
        }))
    }
}
impl std::cmp::Ord for SSAVarDefinition {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other)
            .expect("PartialCmp always succeeds on SSAVarDefinition")
    }
}

/// The SSA-form computed for the whole program
pub struct SSA {
    /// The SSA variables recovered from the program
    ssa_vars: Vec<SSAVarDefinition>,
    /// The input SSA variables to each instruction
    ins_inputs: Vec<Vec<Variable>>,
    /// The output SSA variable for a given instruction (Note: this assumes that instructions can have only upto 1 output)
    ins_output: Vec<Option<Variable>>,
    /// A read-only reference to the program
    pub program: Rc<Program>,
}

impl SSA {
    /// Compute the SSA IR for a given `program`
    pub fn compute_from(program: &Rc<Program>) -> Self {
        let summary = ProgramSummary::compute_from(program);

        let mut ssa_vars: InsertionOrderedSet<SSAVarDefinition> = InsertionOrderedSet::new();
        let mut ins_inputs: Vec<Vec<Variable>> =
            vec![Default::default(); program.instructions.len()];
        let mut ins_output: Vec<Option<Variable>> =
            vec![Default::default(); program.instructions.len()];

        for (func_id, (_func_name, _unaff_vars, bbidxs, _entry)) in
            program.functions.iter().enumerate()
        {
            debug!("Computing SSA IR for function"; "func_id" => func_id, "func_name" => _func_name);
            let reaching_defs =
                DataFlow::<ReachingDefinitionsElement>::forward_analyze(&summary, func_id);
            let func_il_addrs = bbidxs
                .iter()
                .flat_map(|&bbidx| program.basic_blocks[bbidx].iter())
                .cloned()
                .collect::<Vec<usize>>();

            for il_pc in func_il_addrs {
                for (inpidx, inp) in summary.inputs[il_pc].iter().enumerate() {
                    if let Some(v) = inp {
                        let used_def_insns = reaching_defs
                            .ins
                            .get(&il_pc)
                            .unwrap()
                            .defs
                            .get(v)
                            .unwrap()
                            .iter()
                            .map(|ProgPoint::Insn(p)| *p);
                        let phi_node = SSAVarDefinition::PhiNode(
                            used_def_insns
                                .map(|iladdr| {
                                    SSAVariable(ssa_vars.insert(
                                        match program.instructions[iladdr].op {
                                            Op::FunctionStart => {
                                                SSAVarDefinition::ValueAtFunctionStart(iladdr, *v)
                                            }
                                            _ => SSAVarDefinition::ILInstruction(iladdr, *v),
                                        },
                                    ))
                                })
                                .collect(),
                        );
                        let var = match phi_node {
                            SSAVarDefinition::PhiNode(vs) if vs.len() == 1 => {
                                vs.into_iter().next().unwrap()
                            }
                            _ => SSAVariable(ssa_vars.insert(phi_node)),
                        };
                        ins_inputs[il_pc].push(Variable::Variable { var });
                    } else {
                        let v = match program.instructions[il_pc].inputs[inpidx] {
                            il::Variable::Constant { value, .. } => Variable::ConstantValue {
                                progpoint: ProgPoint::Insn(il_pc),
                                value,
                                input_posn_in_il_insn: inpidx,
                            },
                            il::Variable::MachineAddress { .. }
                            | il::Variable::ILAddress { .. }
                            | il::Variable::ILOffset { .. } => Variable::ValueIrrelevantConstant,
                            il::Variable::Unused
                            | il::Variable::Varnode { .. }
                            | il::Variable::DerefVarnode { .. }
                            | il::Variable::StackVariable { .. } => unreachable!(),
                        };
                        ins_inputs[il_pc].push(v);
                    }
                }
                for v in summary.outputs[il_pc].iter().flatten() {
                    // XXX: This assumes we can have at max only 1 output per instruction
                    ins_output[il_pc] = Some(Variable::Variable {
                        var: SSAVariable(
                            ssa_vars.insert(SSAVarDefinition::ILInstruction(il_pc, *v)),
                        ),
                    });
                }
            }
        }

        // TODO: Do any phi-node optimization opportunities remain anymore?

        let ret = Self {
            ssa_vars: ssa_vars.into_vec(),
            ins_inputs,
            ins_output,
            program: program.clone(),
        };

        ret.dump_to_trace();

        ret
    }

    /// An iterator over all phi nodes in the program
    pub fn phi_nodes_iter(
        &self,
    ) -> impl std::iter::Iterator<Item = (SSAVariable, &UnorderedSet<SSAVariable>)> {
        self.ssa_vars
            .iter()
            .enumerate()
            .filter_map(|(i, v)| match v {
                SSAVarDefinition::PhiNode(vs) => Some((SSAVariable(i), vs)),
                _ => None,
            })
    }

    /// Provides a debugging-friendly view on the program
    pub fn debug_program(
        &self,
        show_machine_addr: bool,
        highlight_il_addr: Option<usize>,
    ) -> DebugProgram {
        DebugProgram {
            ssa: self,
            show_machine_addr,
            highlight_il_addr,
        }
    }

    /// Get the function inputs at IL instruction address `il_pc`
    pub fn get_function_inputs(&self, il_pc: usize) -> Vec<Variable> {
        assert_eq!(self.program.instructions[il_pc].op, il::Op::FunctionStart);
        self.ssa_vars
            .iter()
            .enumerate()
            .filter_map(|(i, v)| match v {
                SSAVarDefinition::ValueAtFunctionStart(ilpc, _) if *ilpc == il_pc => {
                    Some(Variable::Variable {
                        var: SSAVariable(i),
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    }

    /// Get the input variable at index `i` at IL instruction address `il_pc`
    pub fn get_input_variable(&self, il_pc: usize, i: usize) -> Variable {
        self.ins_inputs[il_pc][i].clone()
    }

    /// Get the variable impacted by the output at IL instruction address `il_pc`.
    ///
    /// NOTE: Here we again make the assumption that the instruction itself has at max one output.
    pub fn get_output_impacted_variable(&self, il_pc: usize) -> Option<Variable> {
        self.ins_output[il_pc].clone()
    }

    /// Get the output variable at IL instruction address `il_pc`. Note: this is simply a quick
    /// convenience function. It is always guaranteed to be equal to
    /// [`Self::get_output_impacted_variable`]`.unwrap()`.
    pub fn get_output_variable(&self, il_pc: usize) -> Variable {
        self.get_output_impacted_variable(il_pc).unwrap()
    }

    /// Check if variable `v` is an effective constant (i.e., either directly a constant, or
    /// computed from only constants)
    pub fn is_effectively_constant(&self, v: Variable) -> bool {
        let mut checked: UnorderedSet<usize> = Default::default();
        let mut yet_to_check: Vec<usize> =
            self.get_all_immediately_affecting_instructions(v).collect();

        while let Some(il_pc) = yet_to_check.pop() {
            if !checked.insert(il_pc) {
                // Already checked, there is some recursion happening, cannot be constant.
                return false;
            }
            if matches!(
                self.program.instructions[il_pc].op,
                Op::FunctionStart
                    | Op::CallWithFallthrough
                    | Op::CallWithFallthroughIndirect
                    | Op::CallWithNoFallthrough
                    | Op::CallWithNoFallthroughIndirect
            ) {
                // A value that came in from the function start as an argument or via calls, is not considered constant.
                return false;
            }
            // Check if all inputs to this instruction are constants
            for (i, _inp) in self.ins_inputs[il_pc].iter().enumerate() {
                // We do this by adding all instructions that might affect the variable to the
                // instructions to still be checked.
                yet_to_check.extend(
                    self.get_all_immediately_affecting_instructions(
                        self.get_input_variable(il_pc, i),
                    ),
                );
            }
        }

        // No evidence of non-const-ness has been found, thus it must be const
        true
    }

    /// Get all instructions (as IL addresses) that immediately affect the variable `v`'s value
    pub fn get_all_immediately_affecting_instructions(
        &self,
        v: Variable,
    ) -> Box<dyn Iterator<Item = usize> + '_> {
        match v {
            Variable::ConstantValue { .. } | Variable::ValueIrrelevantConstant => {
                Box::new(std::iter::empty())
            }
            Variable::Variable { var } => match &self.ssa_vars[var.0] {
                SSAVarDefinition::ILInstruction(p, _)
                | SSAVarDefinition::ValueAtFunctionStart(p, _) => Box::new(std::iter::once(*p)),
                SSAVarDefinition::PhiNode(vs) => {
                    // Note: as a convenience for code, I assume that phi nodes cannot point into
                    // phi nodes leading to a cascade and potentially infinite recursion here. This
                    // is runtime checked with the following assert, so if the assertion fails, then
                    // we need to restructure this code to handle it better
                    assert!(!vs
                        .iter()
                        .any(|v| matches!(self.ssa_vars[v.0], SSAVarDefinition::PhiNode(_))));
                    Box::new(vs.iter().flat_map(|&var| {
                        self.get_all_immediately_affecting_instructions(Variable::Variable { var })
                    }))
                }
            },
        }
    }

    /// Get the first matching (collection of) variables for an IL variable `il_var` in function
    /// `func_id`, if they exist, returning `None` otherwise
    ///
    /// XXX: Reconsider function signature
    pub fn get_first_matching_variables_for(
        &self,
        il_var: &il::Variable,
        func_id: usize,
    ) -> Option<Vec<Variable>> {
        self.get_matching_variables_for(il_var, func_id, true)
    }

    /// Get all matching (collection of) variables for an IL variable `il_var` in function
    /// `func_id`, if they exist, returning `None` otherwise
    ///
    /// XXX: Reconsider function signature
    pub fn get_all_matching_variables_for(
        &self,
        il_var: &il::Variable,
        func_id: usize,
    ) -> Option<Vec<Variable>> {
        self.get_matching_variables_for(il_var, func_id, false)
    }

    /// Get the matching (collection of) variables for an IL variable `il_var` in function
    /// `func_id`, if it exists, returning `None` otherwise. `first_only` helps choose between
    /// returning just the first matching variables or all matching variables in the function.
    ///
    /// TODO: Performance improvement, currently it does a full traversal over the function.
    ///
    /// XXX: This code is copied (with very minor changes) over from the old `use_def_chains` IR,
    /// and thus does not properly account for phi nodes. It should be updated as necessary.
    ///
    /// XXX: Reconsider function signature
    fn get_matching_variables_for(
        &self,
        il_var: &il::Variable,
        func_id: usize,
        first_only: bool,
    ) -> Option<Vec<Variable>> {
        let result = self
            .get_all_normal_vars_of_function(func_id)
            .into_iter()
            .filter(|(ilv, _)| ilv == il_var)
            .map(|(_, ssav)| ssav)
            .collect::<Vec<_>>();

        if result.is_empty() {
            None
        } else if first_only {
            Some(vec![result.into_iter().next().unwrap()])
        } else {
            Some(result)
        }
    }

    /// Get all (normal, non-phi) variables seen as input or output in a function
    pub(crate) fn get_all_normal_vars_of_function(
        &self,
        func_id: usize,
    ) -> Vec<(il::Variable, Variable)> {
        let (_func_name, _unaff_vars, bbidxs, _entry) = &self.program.functions[func_id];

        let func_il_addrs = bbidxs
            .iter()
            .flat_map(|&bbidx| self.program.basic_blocks[bbidx].iter())
            .cloned()
            .collect::<UnorderedSet<usize>>();
        let func_start_il_addr = *func_il_addrs
            .iter()
            .find(|&&il_addr| self.program.instructions[il_addr].op == Op::FunctionStart)
            .unwrap();

        let mut result = vec![];

        let mut remaining = func_il_addrs;
        let mut queue: VecDeque<usize> = Default::default();
        queue.push_back(func_start_il_addr);
        while let Some(il_addr) = queue.pop_front() {
            if !remaining.remove(&il_addr) {
                continue;
            }
            // Inputs should come before outputs, in case ordering matters
            for (i, inp) in self.program.instructions[il_addr].inputs.iter().enumerate() {
                if !matches!(inp, il::Variable::Unused) {
                    result.push((inp.clone(), self.get_input_variable(il_addr, i)));
                }
            }
            if let Some(o) = self.get_output_impacted_variable(il_addr) {
                result.push((self.program.instructions[il_addr].output.clone(), o));
            }
            for succ in self
                .program
                .get_successor_instruction_addresses_for(il_addr)
            {
                queue.push_back(succ);
            }
        }
        result
    }

    /// Check if given variable `v` is effectively equal to `sp + offset`
    pub fn is_variable_effectively_equal_to_sp_offset(
        &self,
        v: Variable,
        sp: Variable,
        offset: i64,
    ) -> bool {
        let (orig_v, mut v, mut offset) = (v.clone(), v, offset);
        // XXX: This 100 here is an arbitrary upper bound for how deep to search. Most often, we
        // shouldn't even need to go that deep. This should probably be switched out to an infinite
        // loop if we can guarantee that there won't be infinite chains?
        for _ in 0..100 {
            if offset == 0 && v == sp {
                return true;
            }
            let sv = match v {
                Variable::ValueIrrelevantConstant | Variable::ConstantValue { .. } => return false,
                Variable::Variable { var } => var,
            };
            let ilpc = match self.ssa_vars[sv.0] {
                SSAVarDefinition::PhiNode(_) | SSAVarDefinition::ValueAtFunctionStart(_, _) => {
                    return false;
                }
                SSAVarDefinition::ILInstruction(ilpc, _) => ilpc,
            };
            let op = self.program.instructions[ilpc].op;
            if matches!(op, Op::Copy) {
                return self.is_variable_effectively_equal_to_sp_offset(
                    self.get_input_variable(ilpc, 0),
                    sp,
                    offset,
                );
            }
            if !matches!(op, Op::IntAdd | Op::IntSub) {
                return false;
            }
            let (a, b) = (
                self.get_input_variable(ilpc, 0),
                self.get_input_variable(ilpc, 1),
            );
            match (a, b) {
                (a @ Variable::Variable { var: _ }, Variable::ConstantValue { value, .. }) => {
                    offset = match op {
                        Op::IntAdd => offset - value as i64,
                        Op::IntSub => offset + value as i64,
                        _ => unreachable!(),
                    };
                    v = a;
                }
                (Variable::ConstantValue { value, .. }, b @ Variable::Variable { var: _ }) => {
                    offset = match op {
                        Op::IntAdd => offset - value as i64,
                        Op::IntSub => return false,
                        _ => unreachable!(),
                    };
                    v = b;
                }
                _ => return false,
            }
        }
        debug!("Excessively long chain when trying to check SP+offset";
              "orig_v" => ?orig_v, "v" => ?v, "sp" => ?sp);
        false
    }

    /// Get SSA variables involved in a load/store to the stack at the given offset.
    ///
    /// Specifically, this gets the `v`s in the following form of code:
    ///
    /// + `v <- *(initial_sp + offset)`
    /// + `*(initial_sp + offset) <- v`
    ///
    /// Here, `offset` or the `initial_sp + offset` calculation could've been done over multiple
    /// instructions.
    ///
    /// NOTE: Currently, this is implemented as a rudimentary syntactic analysis.
    pub fn get_stack_involved_ssa_variables(
        &self,
        func_id: usize,
        initial_sp: Variable,
        offset: i64,
    ) -> Vec<Variable> {
        let (_func_name, _unaff_vars, bbidxs, _entry) = &self.program.functions[func_id];
        let func_il_addrs = bbidxs
            .iter()
            .flat_map(|&bbidx| self.program.basic_blocks[bbidx].iter())
            .cloned()
            .collect::<UnorderedSet<usize>>();

        func_il_addrs
            .into_iter()
            .filter_map(|il_pc| match self.program.instructions[il_pc].op {
                Op::Load => Some((
                    self.get_output_impacted_variable(il_pc).unwrap(),
                    self.get_input_variable(il_pc, 0),
                )),
                Op::Store => Some((
                    self.get_input_variable(il_pc, 1),
                    self.get_input_variable(il_pc, 0),
                )),
                _ => None,
            })
            .filter(|(_v, p)| {
                self.is_variable_effectively_equal_to_sp_offset(
                    p.clone(),
                    initial_sp.clone(),
                    offset,
                )
            })
            .map(|(v, _p)| v)
            .collect()
    }

    /// Dump collected SSA information to the trace; used purely for debugging purposes
    fn dump_to_trace(&self) {
        slog_scope::scope(
            &slog_scope::logger().new(slog::slog_o!("ssa" => true)),
            || {
                // trace!("Computed SSA form"; "ssa_debug_prog" => ?self.debug_program(true, None));

                for (i, var) in self.ssa_vars.iter().enumerate() {
                    trace!("SSA Variable Definition"; "definition" => ?var, "ssa_var" => ?SSAVariable(i));
                }

                let mut traced_phi_nodes: UnorderedSet<SSAVariable> = Default::default();

                let mut current_func: String = "<<<undefined>>>".into();

                for (pc, ins) in self.program.instructions.iter().enumerate() {
                    if matches!(ins.op, Op::FunctionStart) {
                        current_func = self
                            .program
                            .functions
                            .iter()
                            .filter(|(_, _, bbs, _)| {
                                bbs.iter()
                                    .any(|&bb| self.program.basic_blocks[bb].contains(&pc))
                            })
                            .map(|(fn_name, _, _, _)| fn_name.as_ref())
                            .collect::<Vec<&str>>()
                            .join(", ");

                        let new_defs = self
                            .ssa_vars
                            .iter()
                            .enumerate()
                            .filter_map(|(i, v)| match v {
                                SSAVarDefinition::ValueAtFunctionStart(ilpc, _) if *ilpc == pc => {
                                    Some(format!("{:?}", SSAVariable(i)))
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>();

                        trace!("Function Definition"; "input_vars" => ?new_defs);
                    }

                    macro_rules! var_with_phi {
                        ($v:expr) => {{
                            if traced_phi_nodes.insert($v.clone()) {
                                match &self.ssa_vars[$v.0] {
                                    SSAVarDefinition::ILInstruction(_, _)
                                        | SSAVarDefinition::ValueAtFunctionStart(_, _) => {}
                                    SSAVarDefinition::PhiNode(vs) => {
                                        for x in vs {
                                            // Note: Currently as a simplification, I don't bother looking at phi
                                            // nodes that join other phi nodes, since it'd need recursive prints. If
                                            // necessary, we can definitely add it though. This assert simply makes
                                            // it into a runtime check to ensure that this simplification is not
                                            // going wrong.
                                            assert!(!matches!(self.ssa_vars[x.0], SSAVarDefinition::PhiNode(_)));
                                        }
                                        trace!("Phi Node";
                                               "func" => &current_func,
                                               "output" => ?$v,
                                               "phi_of" => vs.iter().map(|x| format!("{:?}", x)).collect::<Vec<_>>().join(", "));
                                    }
                                }
                            }
                            $v
                        }};
                    }

                    let output = if let Some(o) = &self.ins_output[pc] {
                        match o {
                            Variable::Variable { var } => Some(var_with_phi!(var).to_string()),
                            Variable::ConstantValue { .. } | Variable::ValueIrrelevantConstant => {
                                unreachable!()
                            }
                        }
                    } else {
                        None
                    };

                    let input0 = if let Some(v) = self.ins_inputs[pc].get(0) {
                        Some(match v {
                            Variable::Variable { var } => var_with_phi!(var).to_string(),
                            Variable::ConstantValue { value, .. } => format!("${:#x}", value),
                            Variable::ValueIrrelevantConstant => format!(
                                "{:?}",
                                self.program.instructions[pc].inputs[0]
                                    .machine_addr_to_il_if_possible(&self.program)
                            ),
                        })
                    } else {
                        None
                    };

                    let input1 = if let Some(v) = self.ins_inputs[pc].get(1) {
                        Some(match v {
                            Variable::Variable { var } => var_with_phi!(var).to_string(),
                            Variable::ConstantValue { value, .. } => format!("${:#x}", value),
                            Variable::ValueIrrelevantConstant => format!(
                                "{:?}",
                                self.program.instructions[pc].inputs[1]
                                    .machine_addr_to_il_if_possible(&self.program)
                            ),
                        })
                    } else {
                        None
                    };

                    assert!(self.ins_inputs[pc].len() <= 2);

                    trace!("IL Instruction";
                           "func" => &current_func,
                           "machine_addr" => format_args!("{:#x}", self.program.instructions[pc].address),
                           "pc" => pc,
                           OptionalKV("output", output),
                           "op" => ?ins.op,
                           OptionalKV("input0", input0),
                           OptionalKV("input1", input1),
                    );
                }
            },
        )
    }
}

impl std::fmt::Debug for SSA {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let SSA {
            ssa_vars,
            ins_inputs,
            ins_output,
            program: _,
        } = self;

        struct StrDebugSlice<'a, T>(&'a [T]);
        impl<'a, T: std::fmt::Debug> std::fmt::Debug for StrDebugSlice<'a, T> {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                struct NoQuoteStrDebug(String);
                impl std::fmt::Debug for NoQuoteStrDebug {
                    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "{}", self.0)
                    }
                }
                f.debug_list()
                    .entries(
                        self.0
                            .iter()
                            .enumerate()
                            .map(|(i, x)| NoQuoteStrDebug(format!("{} ~> {:?}", i, x))),
                    )
                    .finish()
            }
        }

        f.debug_struct("SSA")
            .field("ssa_vars", &StrDebugSlice(ssa_vars))
            .field("ins_inputs", &StrDebugSlice(ins_inputs))
            .field("ins_output", &StrDebugSlice(ins_output))
            .finish_non_exhaustive()
    }
}

/// A debugging-friendly view on a program, after SSA has been computed.
pub struct DebugProgram<'a> {
    ssa: &'a SSA,
    show_machine_addr: bool,
    highlight_il_addr: Option<usize>,
}
impl std::fmt::Debug for DebugProgram<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let this = &self.ssa;
        let mut printed_phi_nodes: UnorderedSet<SSAVariable> = Default::default();

        macro_rules! print_var_with_phi {
            ($v:expr) => {{
                if printed_phi_nodes.insert($v.clone()) {
                    match &this.ssa_vars[$v.0] {
                        SSAVarDefinition::ILInstruction(_, _)
                            | SSAVarDefinition::ValueAtFunctionStart(_, _) => {}
                        SSAVarDefinition::PhiNode(vs) => {
                            for x in vs {
                                // Note: Currently as a simplification, I don't bother looking at phi
                                // nodes that join other phi nodes, since it'd need recursive prints. If
                                // necessary, we can definitely add it though. This assert simply makes
                                // it into a runtime check to ensure that this simplification is not
                                // going wrong.
                                assert!(!matches!(this.ssa_vars[x.0], SSAVarDefinition::PhiNode(_)));
                            }
                            writeln!(f, "{:>9} {:?} = 𝛟({})", "...",
                                     $v,
                                     vs.iter().map(|x| format!("{:?}", x)).collect::<Vec<_>>().join(", "))
                                .unwrap(); // Ugh, should be `?` but the unwrap makes it more convenient
                        }
                    }
                }
                format!("{:?}", $v)
            }};
        }

        let mut commented_machine_addrs: UnorderedSet<u64> = Default::default();

        write!(f, "DebugProgram(\n\n")?;
        for (pc, ins) in this.program.instructions.iter().enumerate() {
            if self.highlight_il_addr == Some(pc) {
                writeln!(f, "*******************")?;
            }
            if matches!(ins.op, FunctionStart) {
                writeln!(
                    f,
                    "{}:",
                    this.program
                        .functions
                        .iter()
                        .filter(|(_, _, bbs, _)| bbs
                            .iter()
                            .any(|&bb| this.program.basic_blocks[bb].contains(&pc)))
                        .map(|(fn_name, _, _, _)| fn_name.as_ref())
                        .collect::<Vec<&str>>()
                        .join(":\n")
                )?;

                let new_defs = this
                    .ssa_vars
                    .iter()
                    .enumerate()
                    .filter_map(|(i, v)| match v {
                        SSAVarDefinition::ValueAtFunctionStart(ilpc, _) if *ilpc == pc => {
                            Some(format!("{:?}", SSAVariable(i)))
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if !new_defs.is_empty() {
                    writeln!(f, "    input_vars: {}", new_defs.join(", "))?;
                }
            }
            let machine_addr = if self.show_machine_addr {
                format!(" [{:#x}]", ins.address)
            } else {
                "".into()
            };
            let output = if let Some(o) = &this.ins_output[pc] {
                match o {
                    Variable::Variable { var } => format!("{} = ", print_var_with_phi!(var)),
                    Variable::ConstantValue { .. } | Variable::ValueIrrelevantConstant => {
                        unreachable!()
                    }
                }
            } else {
                "".into()
            };
            let args = this.ins_inputs[pc]
                .iter()
                .enumerate()
                .map(|(i, inp)| match inp {
                    Variable::Variable { var } => print_var_with_phi!(var),
                    Variable::ConstantValue { value, .. } => format!("${:#x}", value),
                    Variable::ValueIrrelevantConstant => format!(
                        "{:?}",
                        this.program.instructions[pc].inputs[i]
                            .machine_addr_to_il_if_possible(&this.program)
                    ),
                })
                .collect::<Vec<_>>()
                .join(", ");
            if CONFIG.debug_print_asm_insns_for_ssa && commented_machine_addrs.insert(ins.address) {
                if let Some(comm) = this.program.machine_insn_comments.get(&ins.address) {
                    writeln!(f, "{:8} ;; {}", "", comm)?;
                }
            }
            if CONFIG.debug_print_il_insns_for_ssa {
                writeln!(f, "{:8} ;; {:?}", "", this.program.instructions[pc])?;
            }
            write!(f, "{:8}{}: {}", pc, machine_addr, output)?;
            use crate::il::Op::*;
            match ins.op {
                Copy => writeln!(f, "{}", args)?,
                Load | Store => writeln!(
                    f,
                    "{:?}{}({})",
                    ins.op,
                    match this.program.instructions[pc].inputs[0] {
                        crate::il::Variable::DerefVarnode { derefval_size, .. } => derefval_size,
                        _ => unreachable!(),
                    },
                    args
                )?,
                FunctionEnd => write!(f, "FunctionEnd\n\n")?,
                _ => writeln!(f, "{:?}({})", ins.op, args)?,
            }
        }
        writeln!(f, ")")
    }
}
