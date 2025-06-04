//! A global store of flags that can impact inference.
//!
//! WARNING: Currently only supports a single consistent configuration amongst threads (i.e., cannot
//! have different configurations for different inference executions in the same process).

/// The global configuration store. Its fields are expected to be accessed across the program via
/// the global [`CONFIG`](static@CONFIG).
pub struct InferenceConfig {
    /// Perform the "clone-and-chop" operation when asked to give a type for a variable with a
    /// requested size that is smaller than the size that was inferred.
    pub allow_size_restriction_based_on_given_variable_size_info: bool,
    /// Perform unification of types at a comparison operation. For example, an observation of the
    /// comparison `a < b` means that `a` and `b` have the same types.
    pub unify_types_on_comparison_ops: bool,
    /// Perform unification of types at a carry/borrow operation.
    pub unify_types_on_carry_or_borrow_ops: bool,
    /// During delayed joining of types, also directly join pointee types. If set to `true`, joins
    /// pointees directly. If set to `false`, sets up a clone-and-join instead.
    pub direct_join_pointees_rather_than_clone_and_join: bool,
    /// During delayed joining of types, also directly join struct fields types. If set to `true`,
    /// joins fields directly. If set to `false`, sets up a clone-and-join instead.
    pub direct_join_struct_fields_rather_than_clone_and_join: bool,
    /// Perform colocation analysis. Without this, it is impossible to detect aggregate (struct or
    /// array) types.
    pub enable_colocation_analysis: bool,
    /// Allow colocation aggregate analysis to influence the "upper bound size" of `struct` members.
    pub allow_aggregate_analysis_to_set_upper_bound_size: bool,
    /// Allow rounding types to primitive C types
    pub enable_type_rounding: bool,
    /// Prefer signed integers over unsigned integers, when performing type rounding. If `false`
    /// then no specific preference is set, but if `true`, then signed are preferred.
    pub prefer_signed_integers_when_rounding: bool,
    /// Signed integers should support all integer operations, while unsigned integers should
    /// support only unsigned operations. If set to `true`, this forces the appearance of _any_
    /// signed operation to instantly mark the integer as signed, while if set to `false`, can lead
    /// to unions of signed and unsigned integers (of same size).
    pub signed_integers_support_all_integer_ops: bool,
    /// Allow type rounding to depend on upper bound size (default to false).
    pub allow_type_rounding_based_on_upper_bound_size: bool,
    /// Perform rounding of an `undefinedN` to the integer type of that size (only applies to
    /// "top-level" `undefinedN`s).
    pub round_up_undefined_n_to_integer: bool,
    /// When computing unions, a union of `uintN_t` and `intN_t` is collapsed.
    pub collapse_union_of_signed_and_unsigned_ints: bool,
    /// Whether types where we only know the size, but nothing else, should be output (default to
    /// true).
    pub allow_outputting_size_only_types_based_on_input: bool,
    /// Whether integers allow multiplication/division of next size as operations within themselves
    /// (default to false). This is intended to potentially account for architectures where that is
    /// how code might be lifted.
    pub additionally_include_next_size_nonlinear_ops_for_integers: bool,
    /// Whether to dump `inference-log-*.dot` files for debugging.
    pub dump_inference_log_dot_files: bool,
    /// Whether to interpret a branch-to-next-insn as a call-with-fallthrough. It appears that
    /// Ghidra, in some circumstances, lifts a `call` instruction to have a `branch` PCode
    /// instruction, rather than its usual choice of a `call` PCode instruction. With this flag
    /// enabled, we switch such modified `branch` instructions back to `call`s.
    pub fix_ghidra_branch_to_next_insn_as_call_with_fallthrough: bool,
    /// Whether to patch the stack pointer after a call and fallthrough. It appears that Ghidra
    /// leaves the RSP/ESP fixing implicit, and it is necessary for us to manually patch it
    /// (otherwise we end up conservatively marking the next usage of the stack pointer as a fresh
    /// havoc'd variable, which is not very helpful, since it completely separates out execution
    /// past a call instruction)
    pub stack_pointer_patch_after_call_fallthrough: bool,
    /// If true, for any calls to an address without a known "unmodified" set, use the set specified
    /// by the same function (approximating the callee's calling convention by the caller's calling
    /// convention)
    pub calling_convention_match_caller_if_unknown_for_callee: bool,
    /// Whether to print IL instructions before each SSA operation (useful when debugging)
    pub debug_print_il_insns_for_ssa: bool,
    /// Whether to print ASM instructions prior to each SSA operation (useful when debugging)
    pub debug_print_asm_insns_for_ssa: bool,
    /// If no variable subset is provided, show only types for function inputs, rather than all
    /// detected SSA variables.
    pub show_only_fn_input_types_if_no_vars_provided: bool,
}

impl InferenceConfig {
    /// Internal method: sets up initialization
    #[allow(static_mut_refs)]
    fn from_initialized() -> Self {
        let init = unsafe {
            INTERNAL_CONFIG_INITIALIZER
                .take()
                .expect("Should be initialized only once")
        };
        init.unwrap_or_default()
    }

    /// Initialize with the given command line configuration. Should only be called once, and should
    /// only be called from `main`.
    #[allow(static_mut_refs)]
    pub fn initialize(command_line_config: Vec<CommandLineInferenceConfig>) {
        let prev = unsafe { INTERNAL_CONFIG_INITIALIZER.replace(Some(command_line_config.into())) };
        assert!(prev.is_some(), "Performed double initialization");
        lazy_static::initialize(&CONFIG);
    }
}

/// Internal initialization detail.
static mut INTERNAL_CONFIG_INITIALIZER: Option<Option<InferenceConfig>> = Some(None);

lazy_static::lazy_static! {
    /// The global configuration store
    pub static ref CONFIG: InferenceConfig = InferenceConfig::from_initialized();
}

#[derive(clap::ArgEnum, Clone, Debug)]
/// Inference configuration parameters
pub enum CommandLineInferenceConfig {
    DisableTypeRounding,
    DisableSizeRestrictingCloneChop,
    DisableComparisonOpBasedUnification,
    DisableCarryBorrowBasedUnification,
    DisableAggregateTypeAnalysis,
    EnableAggregateAnalysisImpactingUpperBoundSize,
    DisableSignedIntegerPreference,
    EnableSignedIntegersSupportAllIntegerOperations,
    DisableTypeRoundingBasedOnUpperBoundSize,
    DisableRoundingUpUndefinedNToInteger,
    DisableCollapseUnionOfSignedAndUnsignedInts,
    DisableOutputForSizeKnownOnlyTypes,
    EnableAdditionallyIncludeNextSizeNonLinearOpsForIntegers,
    CloneAndJoinRatherThanDirectJoinOfPointeesDuringDelayedJoins,
    CloneAndJoinRatherThanDirectJoinOfStructFieldsDuringDelayedJoins,
    DumpInferenceLogDotFiles,
    DisableFixGhidraBranchToNextInsnAsCallWithFallthrough,
    DisableStackPointerPatchAfterCallFallthrough,
    DisableCallingConventionMatchCallerIfUnknownForCallee,
    EnableDebugPrintILInsnsForSSA,
    EnableDebugPrintASMInsnsForSSA,
    EnableShowAllSSAVariablesIfNoVarsFileProvided,
}

impl Default for InferenceConfig {
    fn default() -> Self {
        InferenceConfig {
            allow_size_restriction_based_on_given_variable_size_info: true,
            unify_types_on_comparison_ops: true,
            unify_types_on_carry_or_borrow_ops: true,
            direct_join_pointees_rather_than_clone_and_join: true,
            direct_join_struct_fields_rather_than_clone_and_join: true,
            enable_colocation_analysis: true,
            allow_aggregate_analysis_to_set_upper_bound_size: false,
            enable_type_rounding: true,
            prefer_signed_integers_when_rounding: true,
            signed_integers_support_all_integer_ops: false,
            allow_type_rounding_based_on_upper_bound_size: true,
            round_up_undefined_n_to_integer: true,
            collapse_union_of_signed_and_unsigned_ints: true,
            allow_outputting_size_only_types_based_on_input: true,
            additionally_include_next_size_nonlinear_ops_for_integers: false,
            dump_inference_log_dot_files: false,
            fix_ghidra_branch_to_next_insn_as_call_with_fallthrough: true,
            stack_pointer_patch_after_call_fallthrough: true,
            calling_convention_match_caller_if_unknown_for_callee: true,
            debug_print_il_insns_for_ssa: false,
            debug_print_asm_insns_for_ssa: false,
            show_only_fn_input_types_if_no_vars_provided: true,
        }
    }
}

impl From<Vec<CommandLineInferenceConfig>> for InferenceConfig {
    fn from(v: Vec<CommandLineInferenceConfig>) -> Self {
        use CommandLineInferenceConfig::*;
        let mut r = InferenceConfig::default();
        for v in v {
            match v {
                DisableTypeRounding => {
                    r.enable_type_rounding = false;
                }
                DisableSizeRestrictingCloneChop => {
                    r.allow_size_restriction_based_on_given_variable_size_info = false;
                }
                DisableComparisonOpBasedUnification => {
                    r.unify_types_on_comparison_ops = false;
                }
                DisableCarryBorrowBasedUnification => {
                    r.unify_types_on_carry_or_borrow_ops = false;
                }
                DisableAggregateTypeAnalysis => {
                    r.enable_colocation_analysis = false;
                }
                EnableAggregateAnalysisImpactingUpperBoundSize => {
                    r.allow_aggregate_analysis_to_set_upper_bound_size = true;
                }
                DisableSignedIntegerPreference => {
                    r.prefer_signed_integers_when_rounding = false;
                }
                EnableSignedIntegersSupportAllIntegerOperations => {
                    r.signed_integers_support_all_integer_ops = true;
                }
                DisableTypeRoundingBasedOnUpperBoundSize => {
                    // XXX: Maybe this should be off by default, and require an "enable" command
                    // instead?
                    r.allow_type_rounding_based_on_upper_bound_size = false;
                }
                DisableRoundingUpUndefinedNToInteger => {
                    r.round_up_undefined_n_to_integer = false;
                }
                DisableCollapseUnionOfSignedAndUnsignedInts => {
                    r.collapse_union_of_signed_and_unsigned_ints = false;
                }
                DisableOutputForSizeKnownOnlyTypes => {
                    r.allow_outputting_size_only_types_based_on_input = false;
                }
                EnableAdditionallyIncludeNextSizeNonLinearOpsForIntegers => {
                    r.additionally_include_next_size_nonlinear_ops_for_integers = true;
                }
                CloneAndJoinRatherThanDirectJoinOfPointeesDuringDelayedJoins => {
                    r.direct_join_pointees_rather_than_clone_and_join = false;
                }
                CloneAndJoinRatherThanDirectJoinOfStructFieldsDuringDelayedJoins => {
                    r.direct_join_struct_fields_rather_than_clone_and_join = false;
                }
                DumpInferenceLogDotFiles => {
                    r.dump_inference_log_dot_files = true;
                }
                DisableFixGhidraBranchToNextInsnAsCallWithFallthrough => {
                    r.fix_ghidra_branch_to_next_insn_as_call_with_fallthrough = false;
                }
                DisableStackPointerPatchAfterCallFallthrough => {
                    r.stack_pointer_patch_after_call_fallthrough = false;
                }
                DisableCallingConventionMatchCallerIfUnknownForCallee => {
                    r.calling_convention_match_caller_if_unknown_for_callee = false;
                }
                EnableDebugPrintILInsnsForSSA => {
                    r.debug_print_il_insns_for_ssa = true;
                }
                EnableDebugPrintASMInsnsForSSA => {
                    r.debug_print_asm_insns_for_ssa = true;
                }
                EnableShowAllSSAVariablesIfNoVarsFileProvided => {
                    r.show_only_fn_input_types_if_no_vars_provided = false;
                }
            }
        }
        r
    }
}
