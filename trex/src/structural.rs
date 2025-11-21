//! Structural types from the [`il::Program`](crate::il::Program)

use crate::aggregate_types::Padding;
use crate::containers::unordered::{UnorderedMap, UnorderedMapEntry, UnorderedSet};
use crate::dynamic_variable::dynamic_variable;
use crate::il::{self, ExternalVariable, ILVariableMap, Program};
use crate::inference_config::CONFIG;
use crate::joinable_container::{Container, DelayedJoiner, Index, IndexMap, Joinable};
use crate::log::*;
use crate::serialize_structural::SerializableStructuralTypes;
use crate::ssa::{Variable, SSA};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::rc::Rc;

dynamic_variable! {DONT_DISPLAY_POINTER_TO, with_DONT_DISPLAY_POINTER_TO_set, if_DONT_DISPLAY_POINTER_TO_is_set}
dynamic_variable! {DONT_DISPLAY_AGGR_TYPE, with_DONT_DISPLAY_AGGR_TYPE_set, if_DONT_DISPLAY_AGGR_TYPE_is_set}

// Used to ensure that (independent of what the inference configuration says), force that the
// joining operation will only schedule clone-and-join operations, rather than direct join
// operations
dynamic_variable! {
    FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE,
    with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set,
    if_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_is_set
}

dynamic_variable! {
    FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING,
    with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set,
    if_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_is_set
}

/// Integer operations
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord)]
pub enum IntegerOp {
    Add,
    Sub,
    Mult,
    UDiv,
    SDiv,
    URem,
    SRem,
    And,
    Or,
    Xor,
    Eq,
    Neq,
    ULt,
    SLt,
    UCarry,
    SCarry,
    SBorrow,
    OnesComplement,
    TwosComplement,
    Popcount,
    ZeroExtendSrc,
    SignExtendSrc,
    ZeroExtendTgt,
    SignExtendTgt,
    LeftShift,
    URightShift,
    SRightShift,
    ShiftAmount,
    ConvertToFloat,
    ConvertFromFloatTrunc,
    // Note: If expanded, should update `all_ops`
}

impl IntegerOp {
    /// All integer operations. The iterator is guaranteed to produce these in the same order each
    /// time during execution.
    pub fn all_ops() -> impl IntoIterator<Item = Self> {
        use IntegerOp::*;
        [
            Add,
            Sub,
            Mult,
            UDiv,
            SDiv,
            URem,
            SRem,
            And,
            Or,
            Xor,
            Eq,
            Neq,
            ULt,
            SLt,
            UCarry,
            SCarry,
            SBorrow,
            OnesComplement,
            TwosComplement,
            Popcount,
            ZeroExtendSrc,
            SignExtendSrc,
            ZeroExtendTgt,
            SignExtendTgt,
            LeftShift,
            URightShift,
            SRightShift,
            ShiftAmount,
            ConvertToFloat,
            ConvertFromFloatTrunc,
        ]
    }

    fn is_signed_op(&self) -> Option<bool> {
        // None: both signed and unsigned
        // Some(true): signed only
        // Some(false): unsigned only
        use IntegerOp::*;
        match self {
            Add => None,
            Sub => None,
            Mult => None,
            UDiv => Some(false),
            SDiv => Some(true),
            URem => Some(false),
            SRem => Some(true),
            And => None,
            Or => None,
            Xor => None,
            Eq => None,
            Neq => None,
            ULt => Some(false),
            SLt => Some(true),
            UCarry => Some(false),
            SCarry => Some(true),
            SBorrow => Some(true),
            OnesComplement => None,
            TwosComplement => Some(true),
            Popcount => Some(false),
            ZeroExtendSrc => None,
            SignExtendSrc => Some(true),
            ZeroExtendTgt => None,
            SignExtendTgt => Some(true),
            LeftShift =>
            // XXX: Should this be `None` instead?
            {
                Some(false)
            }
            URightShift => Some(false),
            SRightShift => Some(true),
            ShiftAmount => Some(false),
            ConvertToFloat => Some(true),
            ConvertFromFloatTrunc => Some(true),
        }
    }

    /// All signed integer operations. The iterator is guaranteed to produce these in the same order
    /// each time during execution.
    pub fn signed_ops() -> impl IntoIterator<Item = Self> {
        Self::all_ops()
            .into_iter()
            .filter(|o| o.is_signed_op().unwrap_or(true))
    }

    /// All unsigned integer operations. The iterator is guaranteed to produce these in the same
    /// order each time during execution.
    pub fn unsigned_ops() -> impl IntoIterator<Item = Self> {
        Self::all_ops()
            .into_iter()
            .filter(|o| !o.is_signed_op().unwrap_or(false))
    }

    /// All pointer operations. The iterator is guaranteed to produce these in the same order each
    /// time during execution.
    pub fn all_pointer_ops() -> impl IntoIterator<Item = Self> {
        use IntegerOp::*;
        [
            Add, Sub, And, Or, Xor, Eq, Neq, ULt, SLt, UCarry, SCarry, SBorrow,
        ]
    }

    /// All character operations. The iterator is guaranteed to produce these in the same order each
    /// time during execution.
    pub fn char_ops(signed: bool) -> impl IntoIterator<Item = Self> {
        use IntegerOp::*;
        [
            Add,
            Sub,
            And,
            Or,
            Xor,
            Eq,
            Neq,
            ULt,
            SLt,
            UCarry,
            SCarry,
            SBorrow,
            ZeroExtendSrc,
            SignExtendSrc,
            ZeroExtendTgt,
            SignExtendTgt,
        ]
        .into_iter()
        .filter(move |o| {
            if signed {
                o.is_signed_op().unwrap_or(true)
            } else {
                !o.is_signed_op().unwrap_or(false)
            }
        })
    }
}

/// Boolean operations
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord)]
pub enum BooleanOp {
    Negate,
    And,
    Or,
    Xor,
    // Note: If expanded, should update `all_ops`
}

impl BooleanOp {
    /// All boolean operations. The iterator is guaranteed to produce these in the same order each
    /// time during execution.
    pub fn all_ops() -> impl IntoIterator<Item = Self> {
        use BooleanOp::*;
        [Negate, And, Or, Xor]
    }
}

/// Integer operations
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord)]
pub enum FloatOp {
    Add,
    Sub,
    Mult,
    Div,
    Eq,
    Neq,
    Lt,
    LEq,
    Sqrt,
    Abs,
    Neg,
    Ceil,
    Floor,
    Round,
    ConvertFromInt,
    ConvertToIntTrunc,
    ConvertFromDifferentSizedFloat,
    ConvertToDifferentSizedFloat,
    // Note: If expanded, should update `all_ops`
}

impl FloatOp {
    /// All floating operations. The iterator is guaranteed to produce these in the same order each
    /// time during execution.
    pub fn all_ops() -> impl IntoIterator<Item = Self> {
        use FloatOp::*;
        [
            Add,
            Sub,
            Mult,
            Div,
            Eq,
            Neq,
            Lt,
            LEq,
            Sqrt,
            Abs,
            Neg,
            Ceil,
            Floor,
            Round,
            ConvertFromInt,
            ConvertToIntTrunc,
            ConvertFromDifferentSizedFloat,
            ConvertToDifferentSizedFloat,
        ]
    }
}

/// A recovered structural type which describes how a particular
/// [`Variable`] has been observed to behave.
#[derive(Clone)]
pub struct StructuralType {
    /// The fixed upper bound to the size of the type. If this is set, it cannot have operations
    /// larger than it occur upon it.
    pub upper_bound_size: Option<usize>,
    /// Observed (interpretation-oblivious) copying operations of these sizes in bytes.
    ///
    /// Note: we may sometimes observe copying with multiple sizes, which is why we hold on to a set
    /// of sizes, rather than just one single size.
    pub copy_sizes: UnorderedSet<usize>,
    /// Observed to be compared against zero.
    pub zero_comparable: bool,
    /// Observed to dereference to a known type.
    pub pointer_to: Option<Index>,
    /// Observed to be a boolean (eg: through the result of a comparison)
    pub observed_boolean: bool,
    /// Observed integer operations and their sizes
    pub integer_ops: UnorderedSet<(IntegerOp, usize)>,
    /// Observed boolean operations and their sizes
    pub boolean_ops: UnorderedSet<(BooleanOp, usize)>,
    /// Observed floating operations and their sizes
    pub float_ops: UnorderedSet<(FloatOp, usize)>,
    /// Observed to be code
    pub observed_code: bool,

    /// Observed to have co-located struct fields; the current type refers to the field at offset 0
    ///
    /// Note: Since offset 0 always refers to the current type, allowed field keys are all non-zero.
    ///
    /// Note: Any sizes directly referred to in any type refer to the size of the first element, not
    /// the whole aggregate type (so, for example, `Add(8)` means that the first element supports
    /// 8-byte addition)
    pub colocated_struct_fields: BTreeMap<NonZeroUsize, Index>,
    /// Observed to be an array; the current type refers to members
    pub observed_array: bool,

    /// The rest of the structural type must be ignored if this value is set, since it is referring
    /// to an IL-constant variable. In particular, if this value is set, then joins against it have
    /// no impact. This is used to simplify constraint generation and type recovery from it.
    pub is_type_for_il_constant_variable: bool,
}

/// The aggregate size of a type. See [`StructuralType::aggregate_size`].
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum AggregateSize {
    /// A finite sized type with a definite bound on it.
    Definite(usize),
    /// An indefinite sized struct (i.e., with a flexible member at the end), lower bounded by a
    /// specific size.
    IndefiniteStructLowerBoundedBy(usize),
    /// An indefinite sized array, with specific member size.
    IndefiniteArrayWithElementSize(usize),
    /// Ran out of fuel when trying to analyze the type. Essentially means that too much
    /// struct-in-struct-in-struct-... style behavior was seen.
    IndefiniteOutOfFuel,
}

impl AggregateSize {
    /// Compare two aggregate sizes. Returns `None` if either ran out of fuel, otherwise, indefinite
    /// sizes are mapped to infinity, and are compared.
    ///
    /// Notably, this does **not** satisfy the constraints required on `PartialOrd` and thus should
    /// not be used as a substitute for `PartialOrd`.
    pub fn cmp_with_indefinite_as_infinity(&self, other: &Self) -> Option<std::cmp::Ordering> {
        use std::cmp::Ordering;
        use AggregateSize::*;
        match (self, other) {
            (IndefiniteOutOfFuel, _) | (_, IndefiniteOutOfFuel) => None,
            (Definite(a), Definite(b)) => Some(a.cmp(b)),
            (
                Definite(_),
                IndefiniteStructLowerBoundedBy(_) | IndefiniteArrayWithElementSize(_),
            ) => Some(Ordering::Less),
            (
                IndefiniteStructLowerBoundedBy(_) | IndefiniteArrayWithElementSize(_),
                Definite(_),
            ) => Some(Ordering::Greater),
            (
                IndefiniteStructLowerBoundedBy(_) | IndefiniteArrayWithElementSize(_),
                IndefiniteStructLowerBoundedBy(_) | IndefiniteArrayWithElementSize(_),
            ) => Some(Ordering::Equal),
        }
    }
}

impl StructuralType {
    /// Get the currently observed size (in bytes). Specifically, this means the largest operation
    /// that has been observed on this type.
    pub fn observed_size(&self) -> Option<usize> {
        let mut res: Option<usize> = self.upper_bound_size;

        let mut ignored_claim_msg_printed = false;
        let mut use_sz = |sz: usize| {
            let mut sz = res.unwrap_or(sz).max(sz);
            if let Some(ubs) = self.upper_bound_size {
                if sz > ubs {
                    if !ignored_claim_msg_printed {
                        debug!(
                            "Larger operation size than upper bound size. Ignoring op size.";
                            "stype" => ?self,
                        );
                        ignored_claim_msg_printed = true;
                    }
                    sz = ubs;
                }
            }
            res = Some(sz);
        };

        for &v in &self.copy_sizes {
            use_sz(v);
        }
        for &(_, v) in &self.integer_ops {
            use_sz(v);
        }
        for &(_, v) in &self.float_ops {
            use_sz(v);
        }
        for &(_, v) in &self.boolean_ops {
            use_sz(v);
        }

        res
    }

    /// Set upper bound size, making sure that if it were already set, then it is exactly the same
    /// as what is being set. Returns `false` if failed.
    pub fn set_upper_bound_size(&mut self, upper_bound_size: usize) -> bool {
        if let Some(s) = self.upper_bound_size {
            if s != upper_bound_size {
                debug!("Trying to set different upper bound size value; ignoring";
                      "old" => self.upper_bound_size, "new" => upper_bound_size);
                false
            } else {
                // Nothing to be done
                true
            }
        } else {
            self.upper_bound_size = Some(upper_bound_size);
            true
        }
    }

    /// Get the currently observed aggregate size (in bytes). For a type that includes colocated
    /// types, this combines all field sizes together.
    ///
    /// The `fuel` argument exists to prevent infinitely-recursive types. Any user of this function
    /// should invoke it with `None` for reasonable defaults.
    pub fn aggregate_size(
        &self,
        types: &Container<StructuralType>,
        fuel: Option<usize>,
    ) -> Option<AggregateSize> {
        let fuel = fuel.unwrap_or(10);
        if fuel == 0 {
            return Some(AggregateSize::IndefiniteOutOfFuel);
        }
        let mut res: usize = self.observed_size()?;
        if self.colocated_struct_fields.is_empty() {
            Some(if self.observed_array {
                AggregateSize::IndefiniteArrayWithElementSize(res)
            } else {
                AggregateSize::Definite(res)
            })
        } else {
            if self.observed_array {
                debug!("TODO: Array of structs"; "type" => ?self);
            }
            let mut found_flexible_struct_member = false;
            for (field_offset, fieldidx) in self.colocated_struct_fields.iter() {
                if found_flexible_struct_member {
                    debug!(
                        "Found a flexible struct member in the middle of the type.";
                        "type" => ?self,
                        "field_offset" => field_offset.get(),
                        "field_idx" => ?fieldidx,
                    );
                }
                if res > field_offset.get() {
                    debug!(
                        "Inconsistent struct size+fields. Claimed size of field crosses into next field.";
                        "type" => ?self,
                        "field_offset" => field_offset.get(),
                        "res" => res,
                    );
                }
                res = field_offset.get();
                let field = types.get(*fieldidx);
                match field
                    .aggregate_size(types, Some(fuel - 1))
                    .unwrap_or_else(|| {
                        debug!(
                            "Found field with no aggregate size; assuming size as zero.";
                            "field" => ?field,
                            "field_offset" => field_offset.get(),
                            "field_idx" => ?fieldidx,
                            "type" => ?self,
                        );
                        AggregateSize::Definite(0)
                    }) {
                    AggregateSize::Definite(field_size) => {
                        res += field_size;
                    }
                    AggregateSize::IndefiniteArrayWithElementSize(_elemsize) => {
                        found_flexible_struct_member = true;
                    }
                    AggregateSize::IndefiniteStructLowerBoundedBy(lowerbound) => {
                        res += lowerbound;
                        found_flexible_struct_member = true;
                    }
                    AggregateSize::IndefiniteOutOfFuel => {
                        return Some(AggregateSize::IndefiniteOutOfFuel);
                    }
                }
            }
            Some(if found_flexible_struct_member {
                AggregateSize::IndefiniteStructLowerBoundedBy(res)
            } else {
                AggregateSize::Definite(res)
            })
        }
    }
}

impl Default for StructuralType {
    fn default() -> Self {
        Self {
            upper_bound_size: None,
            copy_sizes: UnorderedSet::new(),
            zero_comparable: false,
            pointer_to: None,
            observed_boolean: false,
            integer_ops: UnorderedSet::new(),
            boolean_ops: UnorderedSet::new(),
            float_ops: UnorderedSet::new(),
            observed_code: false,
            colocated_struct_fields: Default::default(),
            observed_array: false,
            is_type_for_il_constant_variable: false,
        }
    }
}

/// Perform a join of `a` and `b`, picking the `Some` value if either
/// of them is `None`, but if both are `Some`, then uses `f` to
/// perform the join.
#[allow(clippy::many_single_char_names)]
fn opt_join_with<T>(
    a: &mut Option<T>,
    b: Option<T>,
    mut f: impl FnMut(&mut T, T) -> Result<(), T>,
) -> Result<(), Option<T>> {
    match (a.as_mut(), b) {
        (None, None) => {}
        (None, Some(y)) => *a = Some(y),
        (Some(_), None) => {}
        (Some(x), Some(y)) => f(x, y)?,
    };
    Ok(())
}

impl StructuralType {
    fn join_colocated_struct_fields(
        &mut self,
        other: BTreeMap<NonZeroUsize, Index>,
        delayed_joiner: &mut DelayedJoiner,
    ) {
        if other.is_empty() {
            return;
        }
        if self.colocated_struct_fields.is_empty() {
            self.colocated_struct_fields = other;
            return;
        }

        if !other.is_empty() {
            debug!(
                "Both non-empty struct fields when joining.";
                "other" => ?other,
                "self" => ?self.colocated_struct_fields,
            );

            let mut this = std::mem::take(&mut self.colocated_struct_fields)
                .into_iter()
                .collect::<Vec<_>>();
            let other = other.into_iter().collect::<Vec<_>>();

            if this.len() != other.len() {
                info!("Inconsistent struct field lengths found. Picking the shorter length.";
                      "other" => ?other, "self" => ?this);
            }

            let (mut i, mut j) = (0, 0);
            while i < this.len() && j < other.len() {
                if this[i].0 == other[j].0 {
                    let clone_and_join = if_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_is_set(
                        || true,
                        || !CONFIG.direct_join_struct_fields_rather_than_clone_and_join,
                    );
                    if clone_and_join {
                        this[i].1 = delayed_joiner.schedule_clone_and_join(this[i].1, other[j].1);
                    } else {
                        delayed_joiner.schedule(this[i].1, other[j].1);
                    }
                    i += 1;
                    j += 1;
                } else {
                    debug!(
                        "Inconsistent struct joining requested. \
                            Ignoring both sides of struct fields entirely."
                    );
                    trace!("Incosistent struct joining";
                           "other" => ?other, "self" => ?this);
                    return;
                }
            }

            assert!(self.colocated_struct_fields.is_empty() && !this.is_empty());
            self.colocated_struct_fields = this.into_iter().collect();
        }
    }
}

impl Joinable for StructuralType {
    fn join(&mut self, other: Self, delayed_joiner: &mut DelayedJoiner) -> Result<(), Self> {
        if self.is_type_for_il_constant_variable || other.is_type_for_il_constant_variable {
            return Err(other);
        }

        let StructuralType {
            upper_bound_size,
            copy_sizes,
            zero_comparable,
            pointer_to,
            observed_boolean,
            integer_ops,
            boolean_ops,
            float_ops,
            observed_code,
            colocated_struct_fields,
            observed_array,
            is_type_for_il_constant_variable: _,
        } = other;

        opt_join_with(&mut self.upper_bound_size, upper_bound_size, |x, y| {
            if *x != y {
                trace!("Received unequal `upper_bound_size` when joining"; "x" => *x, "y" => y);
            }
            *x = if_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_is_set(
                || (*x).max(y),
                || {
                    // XXX: Should we even be using `min` here?
                    (*x).min(y)
                },
            );
            Ok(())
        })
        .unwrap();

        self.copy_sizes = self.copy_sizes.union(&copy_sizes).cloned().collect();

        self.zero_comparable |= zero_comparable;

        opt_join_with(&mut self.pointer_to, pointer_to, |x, y| {
            if x.surely_equal(&y) {
                // No issues
            } else {
                let clone_and_join = if_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_is_set(
                    || true,
                    || !CONFIG.direct_join_pointees_rather_than_clone_and_join,
                );
                if clone_and_join {
                    *x = delayed_joiner.schedule_clone_and_join(*x, y);
                } else {
                    delayed_joiner.schedule(*x, y);
                }
            };
            Ok(())
        })
        .unwrap();

        self.observed_boolean |= observed_boolean;

        self.integer_ops = self.integer_ops.union(&integer_ops).cloned().collect();
        self.boolean_ops = self.boolean_ops.union(&boolean_ops).cloned().collect();
        self.float_ops = self.float_ops.union(&float_ops).cloned().collect();

        self.observed_code |= observed_code;

        self.join_colocated_struct_fields(colocated_struct_fields, delayed_joiner);
        self.observed_array |= observed_array;

        Ok(())
    }

    fn refers_to<'a>(&'a self) -> Box<dyn std::iter::Iterator<Item = Index> + 'a> {
        let StructuralType {
            upper_bound_size: _,
            copy_sizes: _,
            zero_comparable: _,
            pointer_to,
            observed_boolean: _,
            integer_ops: _,
            boolean_ops: _,
            float_ops: _,
            observed_code: _,
            colocated_struct_fields,
            observed_array: _,
            is_type_for_il_constant_variable,
        } = self;

        let mut res: Box<dyn std::iter::Iterator<Item = Index>> = Box::new([].into_iter());

        if *is_type_for_il_constant_variable {
            return res;
        }

        res = Box::new(res.chain((*pointer_to).into_iter()));

        res = Box::new(res.chain(colocated_struct_fields.values().cloned()));

        res
    }

    fn refers_to_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut Index> + 'a> {
        let StructuralType {
            upper_bound_size: _,
            copy_sizes: _,
            zero_comparable: _,
            pointer_to,
            observed_boolean: _,
            integer_ops: _,
            boolean_ops: _,
            float_ops: _,
            observed_code: _,
            colocated_struct_fields,
            observed_array: _,
            is_type_for_il_constant_variable,
        } = self;

        let mut res: Box<dyn Iterator<Item = &'a mut Index> + 'a> = Box::new([].into_iter());

        if *is_type_for_il_constant_variable {
            return res;
        }

        res = Box::new(res.chain(pointer_to.into_iter()));

        res = Box::new(res.chain(colocated_struct_fields.values_mut()));

        res
    }
}

impl std::fmt::Debug for StructuralType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let StructuralType {
            upper_bound_size,
            copy_sizes,
            zero_comparable,
            pointer_to,
            observed_boolean,
            integer_ops,
            boolean_ops,
            float_ops,
            observed_code,
            colocated_struct_fields,
            observed_array,
            is_type_for_il_constant_variable,
        } = self;
        struct NotShown;
        impl std::fmt::Debug for NotShown {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "...")
            }
        }
        #[derive(PartialEq, Eq, PartialOrd, Ord)]
        struct Ops<T>((T, usize));
        impl<T: std::fmt::Debug> std::fmt::Debug for Ops<T> {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:?}{}", self.0 .0, self.0 .1)
            }
        }
        let not_shown: &dyn std::fmt::Debug = &NotShown;
        if *is_type_for_il_constant_variable {
            return write!(f, "StructuralTypeForILConstantVariable");
        }
        let mut p = f.debug_struct("StructuralType");
        macro_rules! pr {
            (_ $field:ident $v:expr) => {
                p.field(stringify!($field), $v);
            };
            (o $field:ident) => { if let Some(f) = $field { pr!(_ $field f); } };
            (c $field:ident) => { if $field.len() > 0 { pr!(_ $field $field); } };
            (ops $field:ident) => { if $field.len() > 0 { pr!(_ $field &$field.iter()
                                                              .map(|&x| Ops(x))
                                                              .collect::<std::collections::BTreeSet<_>>()); } };
            (b $field:ident) => { if *$field { pr!(_ $field $field); } };
        }
        pr!(o upper_bound_size);
        pr!(c copy_sizes);
        pr!(b zero_comparable);
        if pointer_to.is_some() {
            let x: &dyn std::fmt::Debug = &pointer_to.unwrap();
            pr!(_ pointer_to if_DONT_DISPLAY_POINTER_TO_is_set(|| not_shown, || x));
        }
        pr!(b observed_boolean);
        pr!(ops integer_ops);
        pr!(ops boolean_ops);
        pr!(ops float_ops);
        pr!(b observed_code);
        if !colocated_struct_fields.is_empty() {
            let x: &dyn std::fmt::Debug = colocated_struct_fields;
            pr!(_ colocated_struct_fields if_DONT_DISPLAY_AGGR_TYPE_is_set(|| not_shown, || x));
        }
        pr!(b observed_array);
        p.finish_non_exhaustive()
    }
}

/// A collection of [`Variable`]s and their [`StructuralType`]s. Allows for representing recursive
/// or mutually recursive structural types too.
///
/// Most of the public methods of this type (especially the ones starting with `capability_*`) are
/// not meant to be used outside of [`il::Program`](crate::il::Program). They may disappear/change
/// at any point of time. XXX: Consider using type state or a builder style property to force usage
/// only in `il::Program`?
pub struct StructuralTypes {
    /// A map from locations to type indices.
    type_map: UnorderedMap<Variable, Index>,
    /// A collection of actual structural types, referred to by the type indices.
    types: Container<StructuralType>,
    /// The SSA IR used to find the structural types.
    pub ssa: Rc<SSA>,
}

impl std::fmt::Debug for StructuralTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("StructuralTypes")
            .field(
                "type_map",
                // Force ordering
                &self
                    .type_map
                    .iter()
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
            .field("types", &self.types)
            // If constraints are needed, ask for that debug explicitly
            .finish_non_exhaustive()
    }
}

// XXX: All places where `types.join` shows up is effectively _kinda_
// like unification, except it also performs the equivalent a union of
// the structural types. Not 100% sure what the exact implications
// are, but it is interesting that it _behaves_ similar to
// unification, while at the same time forcing a pair of subtyping
// constraints. Worth thinking more about.

impl StructuralTypes {
    /// Get the (internal) container of types
    pub fn types(&self) -> &Container<StructuralType> {
        &self.types
    }

    /// Mutably get the (internal) container of types
    pub fn types_mut(&mut self) -> &mut Container<StructuralType> {
        &mut self.types
    }

    /// A helper function to make it easier to get the type of a variable, initializing it to the
    /// empty new structural type if necessary.
    fn get_typ_idx_or_default(&mut self, v: Variable) -> Index {
        *self
            .type_map
            .entry(v)
            .or_insert_with(|| self.types.insert_default())
    }

    /// A helper function to make it easier to get access to the `pointer_to` field of a type,
    /// initializing it to the empty new structural type if necessary.
    fn get_pointer_to_or_default(&mut self, typ_idx: Index) -> Index {
        // We are forced to do this dance of constantly re-getting the type from its index because
        // it is possible that the backing store might shift underneath us otherwise when we do an
        // `types.insert_default()`. Thankfully the borrow checker is protecting us here, if we were
        // in C++ or something, this would be a painful one to debug due to subtle pointer
        // incorrectness.
        if self.types[typ_idx].pointer_to.is_none() {
            self.types[typ_idx].pointer_to = Some(self.types.insert_default());
        }
        self.types[typ_idx].pointer_to.unwrap()
    }

    /// A dereference is seen at `v`. `deref_v` is the variable being stored into, if it is a load;
    /// or is the variable that is being stored, if it is a store.
    pub fn capability_deref(
        &mut self,
        v: Variable,
        pointer_size: usize,
        deref_v: Variable,
        deref_size: usize,
    ) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        let deref_idx = self.get_pointer_to_or_default(cur_typ_idx);

        self.types[cur_typ_idx].set_upper_bound_size(pointer_size);
        self.types[deref_idx].copy_sizes.insert(deref_size);

        // The dereferenced type matches the location that was stored into/pulled
        // from.  If `loc` is `deref_loc`, then we will see a location dereferencing
        // into itself, and recursive stuff will automatically get figured out here!
        let deref_loc_typ_idx = *self.type_map.entry(deref_v).or_insert(deref_idx);
        self.types.join(deref_loc_typ_idx, deref_idx);
    }

    /// A comparison of `size` bytes against zero is seen at `v`
    pub fn capability_compared_against_zero(&mut self, v: Variable, size: usize) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        self.types[cur_typ_idx].zero_comparable = true;
        self.types[cur_typ_idx]
            .integer_ops
            .insert((IntegerOp::Eq, size));
    }

    /// A phi-node merge for `from_v` into `v` was observed
    pub fn capability_phi_node(&mut self, v: Variable, from_v: Variable) {
        self.observed_same_type(v, from_v);
    }

    /// A copy of value from `from_v` is seen into `v`
    pub fn capability_copied_from(&mut self, v: Variable, from_v: Variable, size: usize) {
        let from_i = self.get_typ_idx_or_default(from_v.clone());
        let from_t = &self.types[from_i];
        if let Some(sz) = from_t.observed_size() {
            if let Some(mxsz) = from_t.upper_bound_size {
                if mxsz == sz {
                    self.observed_same_type(v.clone(), from_v);
                } else {
                    trace!("TODO[sizedops] differing upper-bounded copy";
                           "v"=>?v, "from_v"=>?from_v, "size"=>size, "sz"=>sz, "mxsz"=>mxsz);
                    self.observed_same_type(v.clone(), from_v);
                }
            } else {
                trace!("TODO[sizedops] non-upper-bounded copy";
                       "v"=>?v, "from_v"=>?from_v, "size"=>size);
                self.observed_same_type(v.clone(), from_v);
            }
        } else {
            trace!("TODO[sizedops] unsized-from-location copy";
                   "v"=>?v, "from_v"=>?from_v, "size"=>size);
            self.observed_same_type(v.clone(), from_v);
        }

        let cur_typ_idx = self.get_typ_idx_or_default(v);
        self.types[cur_typ_idx].copy_sizes.insert(size);
    }

    /// (Internal only) The two variables `v1` and `v2` were observed to have the same type
    fn observed_same_type(&mut self, v1: Variable, v2: Variable) {
        let tidx1 = self.get_typ_idx_or_default(v1);
        let tidx2 = self.get_typ_idx_or_default(v2);
        self.types.join(tidx1, tidx2);
    }

    /// An observation that all variables in the `gvn_set` provided by
    /// [`GlobalValueNumbering`](crate::global_value_numbering::GlobalValueNumbering) belong to the
    /// same type.
    pub fn capability_gvn_congruent(&mut self, gvn_set: impl IntoIterator<Item = Variable>) {
        let mut rem = gvn_set.into_iter();
        if let Some(rep) = rem.next() {
            for mem in rem {
                self.observed_same_type(rep.clone(), mem);
            }
        }
    }

    /// `v` has been seen to behave like a boolean
    pub fn capability_known_boolean(&mut self, v: Variable) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        self.types[cur_typ_idx].observed_boolean = true;
    }

    /// `v` has been seen to have an boolean operation `op`
    pub fn capability_boolean_op(&mut self, v: Variable, op: BooleanOp, size: usize) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        self.types[cur_typ_idx].boolean_ops.insert((op, size));
    }

    /// `v` has been seen to have an integer operation `op`
    pub fn capability_integer_op(&mut self, v: Variable, op: IntegerOp, size: usize) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        self.types[cur_typ_idx].integer_ops.insert((op, size));
    }

    /// `v` has been seen to have an float operation `op`
    pub fn capability_float_op(&mut self, v: Variable, op: FloatOp, size: usize) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        self.types[cur_typ_idx].float_ops.insert((op, size));
    }

    /// `v` is observed to be a pointer to code
    pub fn capability_pointer_to_code(&mut self, v: Variable) {
        let cur_typ_idx = self.get_typ_idx_or_default(v);

        let pointee = self.get_pointer_to_or_default(cur_typ_idx);
        self.types[pointee].observed_code = true;
    }

    /// `v1` and `v2` are observed to be the same type
    pub fn capability_have_same_type(&mut self, v1: Variable, v2: Variable) {
        let ti1 = self.get_typ_idx_or_default(v1);
        let ti2 = self.get_typ_idx_or_default(v2);
        self.types.join(ti1, ti2);
    }

    /// Create a new, empty collection of structural types, holding on to `ssa` for convenient
    /// reference later on.
    ///
    /// The `capability_*` functions introduce variables and their types into the collection.
    pub fn new(ssa: &Rc<SSA>) -> Self {
        let mut type_map: UnorderedMap<Variable, Index> = Default::default();
        let mut types: Container<StructuralType> = Container::new();

        // Introduce the type for IL-constant variables, so that we don't need to do any special
        // handling otherwise when referring to constraints that include constants.
        type_map.insert(
            Variable::ValueIrrelevantConstant,
            types.insert(StructuralType {
                is_type_for_il_constant_variable: true,
                ..Default::default()
            }),
        );

        Self {
            type_map,
            types,
            ssa: ssa.clone(),
        }
    }

    /// Propagate "is a pointer" bidirectionally through pointer arithmetic operations until
    /// fixpoint.
    ///
    /// If we see `result = base + offset`:
    /// - Forward: If `base` is a pointer, then `result` is also a pointer
    /// - Backward: If `result` is a pointer, then `base` is also a pointer
    ///
    /// Note: The pointers may point to different types (e.g., for struct field access).
    pub fn propagate_pointerness_through_arithmetic_constraints(&mut self) {
        let mut changed = true;

        while changed {
            changed = false;

            for il_addr in 0..self.ssa.program.instructions.len() {
                let ins = &self.ssa.program.instructions[il_addr];

                if !matches!(ins.op, crate::il::Op::IntAdd | crate::il::Op::IntSub) {
                    continue;
                }
                let inp0_is_const = matches!(ins.inputs[0], crate::il::Variable::Constant { .. });
                let inp1_is_const = matches!(ins.inputs[1], crate::il::Variable::Constant { .. });
                let base_var_input_idx = if inp0_is_const && !inp1_is_const {
                    1
                } else if !inp0_is_const && inp1_is_const {
                    0
                } else {
                    continue;
                };
                let base_idx = match self
                    .type_map
                    .get(&self.ssa.get_input_variable(il_addr, base_var_input_idx))
                    .copied()
                {
                    Some(idx) => idx,
                    None => continue,
                };
                let result_idx = match self.ssa.get_output_impacted_variable(il_addr) {
                    Some(v) => match self.type_map.get(&v).copied() {
                        Some(idx) => idx,
                        None => continue,
                    },
                    None => continue,
                };

                // Forward propagation: base is pointer => result is pointer
                if self.types.get(base_idx).pointer_to.is_some()
                    && self.types.get(result_idx).pointer_to.is_none()
                {
                    self.types.get_mut(result_idx).pointer_to = Some(self.types.insert_default());
                    changed = true;
                }

                // Backward propagation: result is pointer => base is pointer
                if self.types.get(result_idx).pointer_to.is_some()
                    && self.types.get(base_idx).pointer_to.is_none()
                {
                    self.types.get_mut(base_idx).pointer_to = Some(self.types.insert_default());
                    changed = true;
                }
            }
        }
    }

    /// Canonicalize the [`Index`]es used to refer to types, while also performing internal garbage
    /// collection. These canonicalized indexes are stabled until further modifications are done to
    /// the contained types, in which case, it might be necessary to re-canonicalize.
    pub fn canonicalize_indexes(&mut self) {
        // Canon-ize the roots
        for idx in self.type_map.values_mut() {
            *idx = self.types.get_canonical_index(*idx);
        }

        // GC
        self.types
            .garbage_collect_with_roots(self.type_map.values().cloned());

        // Canon-ize all the types
        //
        // Have to do it this weird way with the `vec` instead of a `UnorderedMap` because I don't
        // expose direct equality on `Index`
        let mut canon_idxs = vec![];
        for obj in self.types.currently_alive_objects_iter() {
            for idx in obj.refers_to() {
                canon_idxs.push((idx, self.types.get_canonical_index(idx)));
            }
        }
        canon_idxs.reverse();
        for obj in self.types.currently_alive_objects_iter_mut() {
            for idx in obj.refers_to_mut() {
                let (kidx, vidx) = canon_idxs.pop().unwrap();
                assert!(idx.surely_equal(&kidx));
                *idx = vidx;
            }
        }
    }

    /// Get the (internal) index of the type at `Variable`
    pub fn get_type_index(&self, location: Variable) -> Option<Index> {
        self.type_map.get(&location).copied()
    }

    /// Check if types are equal at (internal) indexes `a` and `b`
    #[cfg(test)]
    pub fn are_equal_at_indexes(&self, a: Index, b: Index) -> bool {
        self.types.index_eq(a, b)
    }

    /// Get the type at (internal) index `idx`
    pub fn get_type_from_index(&self, idx: Index) -> Option<&StructuralType> {
        Some(self.types.get(idx))
    }

    /// Get the type of the variable `v`
    pub fn get_type_of(&self, v: &Variable) -> Option<&StructuralType> {
        Some(self.types.get(*self.type_map.get(v)?))
    }

    /// Perform a deep clone, creating an entirely disjoint representation of structural types. This
    /// function ensures that the newly created clone's type indexes cannot be used in the original,
    /// and vice-versa.
    pub fn deep_clone(&self) -> Self {
        let Self {
            type_map,
            types,
            ssa,
        } = self;
        let mut r = StructuralTypes::new(ssa);
        r.type_map = type_map.clone();
        r.types = types.deep_clone(r.type_map.values_mut());
        r
    }

    /// Convert the type at index `idx` to a C-like `struct` starting at `v`, with the given
    /// `member_sizes`.
    ///
    /// Note: this does not match up later portions of the struct (i.e., except the first field in
    /// the struct) with the relevant types, instead creating new types for the
    /// elements. [`Self::mark_types_as_equal`] must be used on the relevant field types to produce
    /// useful structs.
    pub fn convert_to_struct(
        &mut self,
        idx: Index,
        member_sizes: impl Iterator<Item = (usize, Padding)> + Clone,
        has_unsized_array_at_end: bool,
    ) {
        let mut member_sizes = member_sizes;
        let (head_size, head_pad) = member_sizes
            .next()
            .expect("Must have at least one member in struct");
        if head_pad != Padding::IsValue {
            debug!("Padding head when converting to struct"; "idx" => ?idx);
        }

        if self.types[idx].observed_array {
            debug!(
                "TODO: Converting an observed-array to a struct. Unclear implications.";
                "idx" => ?idx,
                "typ" => ?self.types[idx],
            )
        }
        let head_of_struct = &mut self.types[idx];
        if CONFIG.allow_aggregate_analysis_to_set_upper_bound_size {
            if !head_of_struct.set_upper_bound_size(head_size) {
                debug!(
                    "Head when converting to struct found to not have expected size";
                    "idx" => ?idx,
                    "size" => head_of_struct.observed_size().unwrap(),
                    "expected" => head_size,
                );
            }
        }

        if !self.types[idx].colocated_struct_fields.is_empty() {
            info!(
                "Attempting to convert type to struct again";
                "idx" => ?idx,
                "previous_colocated" => ?self.types[idx].colocated_struct_fields,
                "sizes" => ?self.types[idx]
                    .colocated_struct_fields
                    .iter()
                    .map(|(k, i)| (k, self.types[*i].observed_size()))
                    .collect::<BTreeMap<_, _>>(),
                "new_sizes" => ?member_sizes.clone().collect::<Vec<_>>(),
            );

            if let Some(prev_unsized_posn) = {
                let (posn, idx) = self.types[idx]
                    .colocated_struct_fields
                    .iter()
                    .rev()
                    .next()
                    .unwrap();
                self.types[*idx].observed_array.then(|| posn.get())
            } {
                if has_unsized_array_at_end {
                    let new_unsized_posn = member_sizes.clone().map(|(sz, _pad)| sz).sum::<usize>();
                    if prev_unsized_posn != new_unsized_posn {
                        debug!(
                            "Inconsistent final unsized-array-at-end location. Using new.";
                            "prev" => prev_unsized_posn,
                            "new" => new_unsized_posn,
                        );
                    }
                }
            }
        }

        let mut members = std::mem::take(&mut self.types[idx].colocated_struct_fields);

        let mut cur_size = head_size;
        for (size, pad) in member_sizes {
            let csize = NonZeroUsize::new(cur_size).unwrap();
            match pad {
                Padding::IsValue => {
                    if let Some(&typ) = members.get(&csize) {
                        if let Some(os) = self.types[typ].observed_size() {
                            if os != size {
                                debug!("Marking type as a different split of previous known struct type";
                                      "idx" => ?idx,);
                            }
                        } else {
                            debug!("No observed size on split of previous known struct type";
                                  "idx" => ?idx);
                        }
                        // XXX: Should we be updating padding here? See GH-8
                    } else {
                        let typ = self.types.insert_default();
                        if CONFIG.allow_aggregate_analysis_to_set_upper_bound_size {
                            self.types[typ].set_upper_bound_size(size);
                        }
                        members.insert(csize, typ);
                    }
                }
                Padding::IsPadding => {
                    // Do nothing, other than just skipping past the field
                }
            }
            cur_size += size;
        }
        if has_unsized_array_at_end {
            // XXX: Can we get size info here?
            let typ = self.types.insert_default();
            self.types[typ].observed_array = true;
            members.insert(NonZeroUsize::new(cur_size).unwrap(), typ);
        }

        self.types[idx].colocated_struct_fields = members;
    }

    /// Convert the type at index `idx` to an array starting at `v`, with the given
    /// `member_element_size`
    pub fn convert_to_array(&mut self, idx: Index, member_element_size: usize) {
        if !self.types[idx].colocated_struct_fields.is_empty() {
            debug!(
                "TODO: Converting a struct to an array. Unclear implications";
                "idx" => ?idx,
                "typ" => ?self.types[idx],
                "member_element_size" => member_element_size,
            );
        }
        if self.types[idx].observed_array {
            info!(
                "Nothing wrong in marking something as array twice, \
                 but I don't actually expect this to happen so this \
                 assert exists as a way to see if there are any \
                 invariants elsewhere in the code that I might've missed";
                "idx" => ?idx,
                "typ" => ?self.types[idx],
                "member_element_size" => member_element_size,
            );
        }
        let head_type = &mut self.types[idx];
        if CONFIG.allow_aggregate_analysis_to_set_upper_bound_size {
            if !head_type.set_upper_bound_size(member_element_size) {
                debug!("Expected head type of array to contain element size";
                  "head_type" => ?head_type,
                  "element_size" => member_element_size);
            }
        }

        self.types[idx].observed_array = true;
    }

    /// Mark the types at indexes `idx1` and `idx2` as equal. This performs a coalescing of their
    /// relevant structural members. This operation should be called only if two types are
    /// known to actually be equal.
    pub fn mark_types_as_equal(&mut self, idx1: Index, idx2: Index) {
        self.types.join(idx1, idx2)
    }

    /// Convert to a machine-readable serializable form, for analysis outside our code
    pub fn serialize(
        &self,
        vars: &Option<ILVariableMap>,
    ) -> SerializableStructuralTypes<ExternalVariable> {
        let vars_stack_pointer = vars
            .as_ref()
            .map(|v| v.stack_pointer.clone())
            .unwrap_or_else(|| {
                (
                    match self.ssa.program.pointer_size {
                        4 => "ESP",
                        8 => "RSP",
                        _ => unimplemented!(),
                    }
                    .into(),
                    il::Variable::Varnode {
                        address_space_idx: self
                            .ssa
                            .program
                            .address_spaces
                            .iter()
                            .position(|a| a.name == "register")
                            .unwrap(),
                        offset: match self.ssa.program.pointer_size {
                            4 => 0x10,
                            8 => 0x20,
                            _ => unimplemented!(),
                        },
                        size: self.ssa.program.pointer_size,
                    },
                )
            });
        let mut stack_pointer_var: UnorderedMap<usize, Variable> = Default::default();
        let mut var_type_list: Vec<(ExternalVariable, usize, Index)> = vec![];
        let mut non_matching_sized_external_variables: Vec<(ExternalVariable, usize)> = {
            // External vars that we couldn't match with internal vars, but know the size for.
            vec![]
        };
        for (extvar, (fnid, ilvars)) in vars.as_ref().iter().flat_map(|vs| &vs.varmap) {
            if self.ssa.program.instructions[self
                .ssa
                .program
                .get_il_addrs_for_machine_addr(self.ssa.program.functions[*fnid].3 .0)
                .unwrap()
                .0]
                .op
                == crate::il::Op::ProcessorException
            {
                // The function instantly causes a processor exception, we should ignore this
                // external variable in our output entirely.
                continue;
            }
            let mut extvarsize: Option<usize> = None;
            for ilvar in ilvars {
                match ilvar {
                    il::Variable::Varnode { size, .. }
                    | il::Variable::StackVariable { var_size: size, .. } => {
                        if let Some(extvarsize) = extvarsize {
                            assert_eq!(extvarsize, *size);
                        } else {
                            extvarsize = Some(*size);
                        }
                    }
                    _ => unreachable!(),
                }
                if let Some(matching_vars) = self
                    .ssa
                    // XXX: Should we be getting all matching variables here?
                    .get_first_matching_variables_for(ilvar, *fnid)
                {
                    trace!("Matching variables"; "extvar" => ?extvar, "matching_vars" => ?matching_vars);
                    for var in matching_vars {
                        var_type_list.push((
                            extvar.clone(),
                            extvarsize.unwrap(),
                            self.get_type_index(var).unwrap(),
                        ));
                    }
                } else if matches!(ilvar, il::Variable::StackVariable { .. }) {
                    trace!("Extvar is a stack variable"; "extvar" => ?extvar, "ilvar" => ?ilvar);
                    let stack_pointer = match stack_pointer_var.entry(*fnid) {
                        UnorderedMapEntry::Occupied(sp) => sp.get().clone(),
                        UnorderedMapEntry::Vacant(v) => {
                            let stack_pointer_vars = self
                                .ssa
                                .get_first_matching_variables_for(&vars_stack_pointer.1, *fnid);
                            let stack_pointer_vars = if let Some(spvs) = stack_pointer_vars {
                                spvs
                            } else {
                                debug!(
                                    "Could not find a stack pointer variable for stack-relative external var";
                                    "extvar" => %extvar, "fnid" => fnid, "sp" => ?vars_stack_pointer
                                );
                                if let Some(extvarsize) = extvarsize {
                                    non_matching_sized_external_variables
                                        .push((extvar.clone(), extvarsize));
                                }
                                continue;
                            };
                            assert_eq!(stack_pointer_vars.len(), 1);
                            v.insert(stack_pointer_vars.into_iter().next().unwrap())
                                .clone()
                        }
                    };
                    let offset = match ilvar {
                        il::Variable::StackVariable {
                            stack_offset: o,
                            var_size: _,
                        } => *o,
                        _ => unreachable!(),
                    };
                    let matching_vars = self.ssa.get_stack_involved_ssa_variables(
                        *fnid,
                        stack_pointer.clone(),
                        offset,
                    );
                    if matching_vars.is_empty() {
                        debug!("Could not get matching internal vars for stack-relative external var";
                              "extvar" => %extvar, "fnid" => fnid, "sp" => ?stack_pointer);
                        if let Some(extvarsize) = extvarsize {
                            non_matching_sized_external_variables
                                .push((extvar.clone(), extvarsize));
                        }
                    } else {
                        // Note: this flattens out stack variables (i.e., if a stack-slot is used
                        // multiple times, then this forces the reuse to become into a union)
                        trace!("Matching variables";
                               "stack" => true,
                               "extvar" => ?extvar,
                               "matching_vars" => ?matching_vars);
                        for var in matching_vars {
                            var_type_list.push((
                                extvar.clone(),
                                extvarsize.unwrap(),
                                self.get_type_index(var).unwrap(),
                            ));
                        }
                    }
                } else {
                    debug!(
                        "Could not get matching internal vars for external var";
                        "extvar" => %extvar,
                        "fnid" => fnid,
                        "ilvars" => ?ilvars,
                    );
                    if let Some(extvarsize) = extvarsize {
                        non_matching_sized_external_variables.push((extvar.clone(), extvarsize));
                    }
                }
            }
        }

        if vars.is_none() {
            assert!(var_type_list.is_empty());
            for (pc, ins) in self.ssa.program.instructions.iter().enumerate() {
                if matches!(ins.op, il::Op::FunctionStart) {
                    let current_func_id = self
                        .ssa
                        .program
                        .functions
                        .iter()
                        .position(|(_, _, bbs, _)| {
                            bbs.iter()
                                .any(|&bb| self.ssa.program.basic_blocks[bb].contains(&pc))
                        })
                        .unwrap();

                    let current_func = &self.ssa.program.functions[current_func_id].0;

                    let function_variables = if CONFIG.show_only_fn_input_types_if_no_vars_provided
                    {
                        self.ssa.get_function_inputs(pc)
                    } else {
                        self.ssa
                            .get_all_normal_vars_of_function(current_func_id)
                            .into_iter()
                            .map(|(_, v)| v)
                            .filter(|v| match v {
                                Variable::Variable { .. } => true,
                                Variable::ConstantValue { .. }
                                | Variable::ValueIrrelevantConstant => false,
                            })
                            .collect::<UnorderedSet<_>>()
                            .into_iter()
                            .collect()
                    };

                    for v in function_variables {
                        if let Some(t) = self.get_type_index(v.clone()) {
                            var_type_list.push((
                                ExternalVariable(format!("{v:?}@{current_func}")),
                                self.types.get(t).observed_size().unwrap_or_default(),
                                t,
                            ));
                        } else {
                            debug!(
                                "Missing type for variable";
                                "current_func" => &current_func,
                                "v" => ?v,
                            );
                        }
                    }
                }
            }
        }

        let mut types = self
            .types
            .deep_clone(var_type_list.iter_mut().map(|x| &mut x.2));

        let mut varmap: BTreeMap<ExternalVariable, Index> = Default::default();
        let mut restriction_map_cache = IndexMap::new();

        for (extvar, extvarsize, typidx) in var_type_list.into_iter() {
            let typidx = if CONFIG.allow_size_restriction_based_on_given_variable_size_info {
                get_equivalent_index_with_restricted_aggregate_size(
                    &mut restriction_map_cache,
                    &mut types,
                    typidx,
                    extvarsize,
                    &self.ssa.program,
                )
            } else {
                typidx
            };
            if let Some(previdx) = varmap.get(&extvar) {
                // XXX: Is joining reasonable here?
                types.join(*previdx, typidx);
            } else {
                varmap.insert(extvar, typidx);
            }
        }

        if CONFIG.allow_outputting_size_only_types_based_on_input {
            for (extvar, extvarsize) in non_matching_sized_external_variables.into_iter() {
                if let Some(&previdx) = varmap.get(&extvar) {
                    let successful_upper_bound =
                        types.get_mut(previdx).set_upper_bound_size(extvarsize);
                    if !successful_upper_bound {
                        debug!(
                            "Conflicting upper bound sizes";
                            "extvar" => ?extvar,
                        );
                    }
                } else {
                    let mut typ = StructuralType::default();
                    let successful_upper_bound = typ.set_upper_bound_size(extvarsize);
                    assert!(successful_upper_bound);
                    varmap.insert(extvar, types.insert(typ));
                }
            }
        }

        let type_names = Default::default(); // Allow auto-picking names for types
        SerializableStructuralTypes::new(varmap, type_names, types)
    }

    /// Write a `.dot` file representing these structural types
    pub fn write_dot(
        &self,
        w: &mut impl std::io::Write,
        highlight_il_addr: Option<usize>,
    ) -> std::io::Result<()> {
        #[derive(Clone)]
        enum Node {
            Variable(Variable),
            Type(Index),
            Program,
        }
        impl PartialEq<Node> for Node {
            fn eq(&self, other: &Node) -> bool {
                match (self, other) {
                    (Node::Variable(v1), Node::Variable(v2)) => v1 == v2,
                    (Node::Type(t1), Node::Type(t2)) => t1.surely_equal(t2),
                    (Node::Program, Node::Program) => true,
                    _ => false,
                }
            }
        }
        impl Eq for Node {}
        impl std::hash::Hash for Node {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                match self {
                    Node::Variable(v) => {
                        state.write_u8(0);
                        v.hash(state);
                    }
                    Node::Type(t) => {
                        state.write_u8(1);
                        state.write(t.to_string().as_bytes());
                    }
                    Node::Program => {
                        state.write_u8(2);
                    }
                }
            }
        }
        impl PartialOrd for Node {
            fn partial_cmp(&self, other: &Node) -> Option<std::cmp::Ordering> {
                let t = |x: &Node| match x {
                    Node::Program => 0,
                    Node::Variable(_) => 1,
                    Node::Type(_) => 2,
                };
                Some(match t(self).partial_cmp(&t(other))? {
                    std::cmp::Ordering::Equal => match (self, other) {
                        (Node::Variable(v1), Node::Variable(v2)) => v1.partial_cmp(v2)?,
                        (Node::Type(t1), Node::Type(t2)) => t1.some_consistent_ordering(t2),
                        _ => unreachable!(),
                    },
                    ord => ord,
                })
            }
        }
        impl Ord for Node {
            fn cmp(&self, other: &Node) -> std::cmp::Ordering {
                self.partial_cmp(other).unwrap()
            }
        }
        type Edge = (Node, Node, String);

        struct Graph<'a> {
            strtypes: &'a StructuralTypes,
            show_constants: bool,
            show_machine_addr: bool,
            highlight_il_addr: Option<usize>,
        }

        let g = Graph {
            strtypes: self,
            show_constants: false,
            show_machine_addr: true,
            highlight_il_addr,
        };

        impl<'a> dot::Labeller<'a, Node, Edge> for Graph<'a> {
            fn graph_id(&'a self) -> dot::Id<'a> {
                dot::Id::new("StructuralTypes").unwrap()
            }
            fn node_id(&'a self, n: &Node) -> dot::Id<'a> {
                dot::Id::new(match n {
                    Node::Variable(Variable::Variable { var }) => format!("{}", var),
                    Node::Variable(Variable::ConstantValue { value, .. }) => format!("c{}", value),
                    Node::Variable(Variable::ValueIrrelevantConstant) => "viConst".to_string(),
                    Node::Type(i) => format!("t{}", i.to_string()),
                    Node::Program => "program".to_string(),
                })
                .unwrap()
            }
            fn node_label<'b>(&'b self, n: &Node) -> dot::LabelText<'b> {
                match n {
                    Node::Variable(Variable::Variable { var }) => {
                        dot::LabelText::label(format!("{}", var))
                    }
                    Node::Variable(Variable::ConstantValue { value, .. }) => {
                        dot::LabelText::label(format!("${:#x}", value))
                    }
                    Node::Variable(Variable::ValueIrrelevantConstant) => unreachable!(),
                    Node::Type(i) => {
                        let name = format!(
                            "t{}",
                            self.strtypes.types.get_canonical_index(*i).to_string()
                        );
                        let typ = with_DONT_DISPLAY_POINTER_TO_set(|| {
                            with_DONT_DISPLAY_AGGR_TYPE_set(|| {
                                format!("{:#?}", self.strtypes.types[*i])
                            })
                        });
                        dot::LabelText::escaped(format!(
                            "{}\n\n{}\\l",
                            name,
                            typ.replace('\n', "\\l")
                        ))
                    }
                    Node::Program => {
                        let debug_prog = self
                            .strtypes
                            .ssa
                            .debug_program(self.show_machine_addr, self.highlight_il_addr);
                        dot::LabelText::escaped(
                            format!("{:?}", debug_prog)
                                .replace('\n', "\\l")
                                .replace('𝛟', "&#934;"),
                        )
                    }
                }
            }
            fn node_shape(&'a self, n: &Node) -> Option<dot::LabelText<'a>> {
                match n {
                    Node::Variable(_) | Node::Type(_) => None,
                    Node::Program => Some(dot::LabelText::label("note")),
                }
            }
            fn edge_label<'b>(&'b self, e: &Edge) -> dot::LabelText<'b> {
                dot::LabelText::label(e.2.clone())
            }
        }

        fn get_nodes_and_edges(
            s: &StructuralTypes,
            show_constants: bool,
        ) -> (Vec<Node>, Vec<Edge>) {
            let mut edges: Vec<Edge> = vec![];

            let mut visited: std::collections::BTreeSet<Node> =
                std::iter::once(Node::Program).collect();
            let mut worklist: Vec<Node> = s
                .type_map
                .iter()
                .filter_map(|(v, _)| match v {
                    Variable::ValueIrrelevantConstant => None,
                    Variable::ConstantValue { .. } => {
                        show_constants.then(|| Node::Variable(v.clone()))
                    }
                    Variable::Variable { .. } => Some(Node::Variable(v.clone())),
                })
                .collect();

            while let Some(n) = worklist.pop() {
                if !visited.insert(n.clone()) {
                    // Already visited
                    continue;
                }
                match &n {
                    Node::Variable(v) => {
                        let t =
                            Node::Type(s.types.get_canonical_index(*s.type_map.get(v).unwrap()));
                        worklist.push(t.clone());
                        edges.push((n.clone(), t, "has_type".into()));
                    }
                    Node::Type(ti) => {
                        let t = &s.types[*ti];
                        if let Some(i) = t.pointer_to {
                            let i = s.types.get_canonical_index(i);
                            worklist.push(Node::Type(i));
                            edges.push((Node::Type(*ti), Node::Type(i), "pointer_to".into()));
                        }
                        for (offset, i) in t.colocated_struct_fields.iter() {
                            let i = s.types.get_canonical_index(*i);
                            worklist.push(Node::Type(i));
                            edges.push((
                                Node::Type(*ti),
                                Node::Type(i),
                                format!("struct_field_{}", offset),
                            ));
                        }
                    }
                    Node::Program => unreachable!(),
                }
            }

            (visited.into_iter().collect(), edges)
        }

        impl<'a> dot::GraphWalk<'a, Node, Edge> for Graph<'a> {
            fn nodes(&self) -> dot::Nodes<'a, Node> {
                get_nodes_and_edges(self.strtypes, self.show_constants)
                    .0
                    .into()
            }
            fn edges(&'a self) -> dot::Edges<'a, Edge> {
                get_nodes_and_edges(self.strtypes, self.show_constants)
                    .1
                    .into()
            }
            fn source(&self, e: &Edge) -> Node {
                e.0.clone()
            }
            fn target(&self, e: &Edge) -> Node {
                e.1.clone()
            }
        }

        dot::render(&g, w)
    }

    /// Generate a `.dot` file representing these structural types
    pub fn generate_dot(&self, highlight_il_addr: Option<usize>) -> String {
        let mut s: Vec<u8> = vec![];
        self.write_dot(&mut s, highlight_il_addr).unwrap();
        String::from_utf8(s).unwrap()
    }
}

/// Ensures that the type at the output index is the same as that at the input index, but with
/// restricted aggregate size to the given `upper_bound_size`. If the type's aggregate size is
/// already upper bounded by the size, it returns the index unchanged, but if the aggregate size
/// is not restricted, then this will make a copy of the type, with necessary modifications to
/// ensure that aggregate size is lower than upper bound size.
///
/// Note: Should not be used during type inference, but only during final serialization.
///
/// Postcondition: `type_at(return).aggregate_size() <= upper_bound_size`
#[must_use]
pub fn get_equivalent_index_with_restricted_aggregate_size(
    restriction_map_cache: &mut IndexMap<UnorderedMap<usize, Index>>,
    types: &mut Container<StructuralType>,
    idx: Index,
    upper_bound_size: usize,
    program: &Program,
) -> Index {
    if let Some(m) = restriction_map_cache.get(idx) {
        if let Some(tgt_idx) = m.get(&upper_bound_size) {
            return *tgt_idx;
        }
    }

    let typ = types.get(idx);

    if typ.observed_size().is_none() {
        trace!(
            "Trying to restrict size of observed-size-unknown type";
            "idx" => ?idx,
            "requested_upper_bound" => upper_bound_size,
            "typ" => ?types.get(idx),
        );
        let mut newtyp = typ.clone();
        newtyp.upper_bound_size = Some(upper_bound_size);
        // XXX: Should we place it into the `restriction_map_cache`?
        return types.insert(newtyp);
    }

    let tgt_idx = match (
        typ.aggregate_size(types, None).unwrap(),
        typ.observed_size().unwrap(),
    ) {
        (aggsz @ AggregateSize::Definite(sz), _)
        | (aggsz @ AggregateSize::IndefiniteOutOfFuel, sz) => {
            if aggsz == AggregateSize::IndefiniteOutOfFuel {
                debug!("Detected an overly-recursive type. Using only first element and ignoring rest";
                       "observed_size" => typ.observed_size().unwrap(),
                       "requested_upper_bound" => upper_bound_size,
                       "type" => ?typ);
            }
            if sz <= upper_bound_size && aggsz != AggregateSize::IndefiniteOutOfFuel {
                // Type is already in the right bound, just return directly
                return idx;
            } else {
                if typ.observed_size().unwrap() == upper_bound_size {
                    // Removing the colocated fields is sufficient
                    trace!("Aggregate restriction: colocated chop";
                           "observed_size" => typ.observed_size().unwrap(),
                           "requested_upper_bound" => upper_bound_size,
                           "type" => ?typ);
                    let mut newtyp = typ.clone();
                    newtyp.colocated_struct_fields.clear();
                    types.insert(newtyp)
                } else if typ.observed_size().unwrap() > upper_bound_size {
                    // Fields cannot matter at this point, since the local size itself is larger.
                    //
                    // XXX: Is this sort of local chop reasonable to do?
                    //
                    // Note: Matches `IndefiniteStructLowerBoundedBy`'s local chop below, must be kept in sync.
                    trace!("Aggregate restriction: local chop";
                           "observed_size" => typ.observed_size().unwrap(),
                           "requested_upper_bound" => upper_bound_size,
                           "type" => ?typ);
                    let mut newtyp = typ.clone();
                    newtyp.upper_bound_size = Some(upper_bound_size);
                    newtyp.copy_sizes = newtyp
                        .copy_sizes
                        .into_iter()
                        .filter(|&sz| sz <= upper_bound_size)
                        .collect();
                    if upper_bound_size < program.pointer_size && newtyp.pointer_to.is_some() {
                        // Cannot be a pointer, because minimum pointer sizes are not met
                        debug!(
                            "Localchop: non-pointer due to size restrictions";
                            "requested_upper_bound" => upper_bound_size,
                            "pointer_sizes_in_binary" => program.pointer_size,
                            "type" => ?typ,
                        );
                        newtyp.pointer_to = None;
                    }
                    newtyp.integer_ops = newtyp
                        .integer_ops
                        .into_iter()
                        .filter(|&(_op, sz)| sz <= upper_bound_size)
                        .collect();
                    newtyp.boolean_ops = newtyp
                        .boolean_ops
                        .into_iter()
                        .filter(|&(_op, sz)| sz <= upper_bound_size)
                        .collect();
                    newtyp.float_ops = newtyp
                        .float_ops
                        .into_iter()
                        .filter(|&(_op, sz)| sz <= upper_bound_size)
                        .collect();
                    newtyp.colocated_struct_fields.clear();
                    types.insert(newtyp)
                } else {
                    if aggsz == AggregateSize::IndefiniteOutOfFuel {
                        // We reached a situation where we have an overly recursive type which has a
                        // smaller element size. There isn't a clean or easy way for us to clean up,
                        // so we give up on this type and return an unrestricted result.
                        //
                        // XXX: Is there something better we can do here?
                        trace!("Aggregate restriction: smaller elem on overly-recursive type. Giving up.";
                               "aggregate_size" => ?aggsz,
                               "observed_size" => typ.observed_size().unwrap(),
                               "requested_upper_bound" => upper_bound_size,
                               "type" => ?typ);
                        return idx;
                    } else {
                        debug!("TODO: Definite but smaller upper bound size. Giving up and returning the full size.";
                              "aggregate_size" => ?aggsz,
                              "observed_size" => typ.observed_size().unwrap(),
                              "requested_upper_bound" => upper_bound_size,
                              "type" => ?typ);
                        return idx;
                    }
                }
            }
        }
        (AggregateSize::IndefiniteArrayWithElementSize(element_size), sz) => {
            trace!(
                "Restricting type size for indefinite array";
                "element_size" => element_size,
                "idx" => ?idx,
                "typ" => ?typ,
                "requested_upper_bound" => upper_bound_size,
            );
            assert_eq!(sz, element_size);
            let mut newtyp = typ.clone();
            newtyp.observed_array = false;
            let newidx = types.insert(newtyp);
            if element_size > upper_bound_size {
                // We need to break the element apart
                get_equivalent_index_with_restricted_aggregate_size(
                    restriction_map_cache,
                    types,
                    newidx,
                    upper_bound_size,
                    program,
                )
            } else {
                let mut aggtyp = types.get(newidx).clone();
                for i in 1..upper_bound_size / element_size {
                    aggtyp
                        .colocated_struct_fields
                        .insert((i * element_size).try_into().unwrap(), newidx);
                }
                let remainder_size = upper_bound_size % element_size;
                if remainder_size != 0 {
                    aggtyp.colocated_struct_fields.insert(
                        ((upper_bound_size / element_size) * element_size)
                            .try_into()
                            .unwrap(),
                        get_equivalent_index_with_restricted_aggregate_size(
                            restriction_map_cache,
                            types,
                            newidx,
                            remainder_size,
                            program,
                        ),
                    );
                }
                types.insert(aggtyp)
            }
        }
        (aggsz @ AggregateSize::IndefiniteStructLowerBoundedBy(lower_bound), sz) => {
            trace!(
                "Restricting type size for indefinite struct";
                "lower_bound" => lower_bound,
                "idx" => ?idx,
                "typ" => ?typ,
                "requested_upper_bound" => upper_bound_size,
            );
            if sz >= upper_bound_size {
                // First element is sufficient, chop latter types
                let mut newtyp = typ.clone();
                newtyp.colocated_struct_fields.clear();
                newtyp.observed_array = false;
                if sz > upper_bound_size {
                    // But first element is still quite large, chop it
                    //
                    // Note: Matches "local chop" above, must be kept in sync
                    newtyp.upper_bound_size = Some(upper_bound_size);
                    newtyp.copy_sizes = newtyp
                        .copy_sizes
                        .into_iter()
                        .filter(|&sz| sz <= upper_bound_size)
                        .collect();
                    newtyp.integer_ops = newtyp
                        .integer_ops
                        .into_iter()
                        .filter(|&(_op, sz)| sz <= upper_bound_size)
                        .collect();
                }
                types.insert(newtyp)
            } else {
                // We need first element and more.
                //
                // XXX: We can probably do better, but here we just give up and return the full struct.
                debug!(
                    "Indefinite struct, first element chop insufficient. Giving up and returning full struct.";
                    "aggregate_size" => ?aggsz,
                    "requested_upper_bound" => upper_bound_size,
                    "type" => ?typ,
                );
                return idx;
            }
        }
    };
    if types.get(tgt_idx).aggregate_size(types, None)
        != Some(AggregateSize::Definite(upper_bound_size))
    {
        debug!(
            "Non-matching definite size for squished type.";
            "new_type" => ?types.get(tgt_idx),
            "old_type" => ?types.get(idx),
            "expected_definite_size" => ?Some(AggregateSize::Definite(upper_bound_size)),
            "squished_definite_size" => ?types.get(tgt_idx).aggregate_size(types, None),
        );
    }
    if restriction_map_cache.get(idx).is_none() {
        restriction_map_cache.insert(idx, Default::default());
    }
    restriction_map_cache
        .get_mut(idx)
        .unwrap()
        .insert(upper_bound_size, tgt_idx);
    tgt_idx
}
