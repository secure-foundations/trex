//! Recover aggregate type information, such as `struct`s and arrays. Essentially a "size of"
//! analysis.
//!
//! Utilizes the co-location constraints produced by the [`crate::starts_at_analysis`] to infer
//! sizes and locations of aggregate types.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::rc::Rc;

use crate::containers::unordered::UnorderedMap;
use crate::log::*;
use crate::ssa::Variable;
use crate::starts_at_analysis::{CoLocated, Constraint};
use crate::structural::StructuralTypes;

/// Padding information
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Padding {
    IsPadding,
    IsValue,
}

/// An aggregate type either has a finite size (i.e., normal C `struct` structs), a "semi-finite"
/// size (i.e., C `struct`s ending with an unsized array parameter), or an infinite size (i.e., C
/// arrays).
enum AggrType {
    /// A C `struct`
    Struct {
        /// The size of each of the atomic member elements of the struct, including any potential
        /// padding.
        member_sizes: Vec<(usize, Padding)>,
        /// True iff the struct has an unsized array at its end, also called a "flexible array
        /// member" (C11, chapter §6.7.2.1).
        ///
        /// For example, `struct { size_t s; int data[]; }`
        has_unsized_array_at_end: bool,
    },
    /// An array of elements
    Array {
        /// The observed size for each atomic element of the array
        member_size: usize,
    },
}

impl std::fmt::Debug for AggrType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AggrType::Struct {
                member_sizes,
                has_unsized_array_at_end,
            } => {
                let mut f = f.debug_struct("DebugCStruct");
                let mut start = 0;
                for (s, p) in member_sizes {
                    match p {
                        Padding::IsPadding => {
                            f.field(&format!("pad__{}", start), s);
                        }
                        Padding::IsValue => {
                            f.field(&format!("val__{}", start), s);
                        }
                    }
                    start += s;
                }
                if *has_unsized_array_at_end {
                    f.field("unsized_array_at_end", &true);
                }
                f.finish()
            }
            AggrType::Array { member_size } => f
                .debug_struct("DebugCArray")
                .field("member_size", member_size)
                .finish(),
        }
    }
}

/// An analysis-internal type, to aid in easy splitting and increasing of type sizes.
struct SquishySize {
    /// A map from starting locations to sizes. Invariant maintained: the sizes will not overlap.
    sizes: BTreeMap<usize, usize>,
    /// Whether non-constant accesses have been discovered yet
    non_constant_access: bool,
    /// Whether negative offsets have been seen. This likely means that it is not behaving like a
    /// normal C-struct.
    negative_offsets_observed: bool,
}

impl SquishySize {
    /// New empty squishy size
    fn new() -> Self {
        Self {
            sizes: Default::default(),
            non_constant_access: false,
            negative_offsets_observed: false,
        }
    }

    /// Constrain size at `loc` to a max of `len` bytes
    fn constrain(&mut self, loc: usize, len: usize) {
        assert_ne!(len, 0);
        // Check clashes on left, and insert as needed
        match self.sizes.range(0..=loc).rev().next() {
            None => {
                // No value found before or at `loc`
                self.sizes.insert(loc, len);
            }
            Some((&k, &v)) => {
                if k == loc {
                    // Value found at `loc`
                    if v < len {
                        info!(
                            "Differing sizes, ignoring longer new size";
                            "old" => v,
                            "new" => len,
                        );
                    } else if v == len {
                        // Nothing to be done
                    } else {
                        // v > len
                        info!(
                            "Differing sizes, performing splitting";
                            "old" => v,
                            "new" => len,
                        );
                        *self.sizes.get_mut(&k).unwrap() = len;
                        self.sizes.insert(k + len, v - len);
                    }
                } else {
                    // Value found before `loc`
                    self.sizes.insert(loc, len);
                    if k + v <= loc {
                        // No clash
                    } else {
                        // Clash, perform split
                        debug!(
                            "Clash found, performing splitting";
                            "old" => ?(k, v),
                            "new" => ?(loc, len),
                        );
                        *self.sizes.get_mut(&k).unwrap() = loc - k;
                    }
                }
            }
        }
        // Check clashes on right, and split as necessary
        match self.sizes.range(loc + 1..).next() {
            None => {
                // Nothing it can clash with
            }
            Some((k, v)) => {
                if loc + len <= *k {
                    // No clash
                } else {
                    // Clash, perform split
                    debug!(
                        "Clash found on right, performing splitting";
                        "new" => ?(loc, len),
                        "old" => ?(k, v),
                    );
                    *self.sizes.get_mut(&loc).unwrap() = k - loc;
                }
            }
        }
    }

    /// Convert to a C-like type
    fn to_c_like_type(self) -> Option<AggrType> {
        if self.negative_offsets_observed {
            None
        } else {
            if self.non_constant_access && self.sizes.len() == 1 {
                assert_eq!(self.sizes.keys().next(), Some(&0));
                Some(AggrType::Array {
                    member_size: *self.sizes.values().next().unwrap(),
                })
            } else {
                let mut start = 0;
                let mut member_sizes = vec![];
                for (k, v) in self.sizes.into_iter() {
                    assert!(k >= start);
                    if k > start {
                        member_sizes.push((k - start, Padding::IsPadding));
                    }
                    member_sizes.push((v, Padding::IsValue));
                    start += v;
                }
                Some(AggrType::Struct {
                    member_sizes,
                    has_unsized_array_at_end: self.non_constant_access,
                })
            }
        }
    }
}

/// Discovered aggregate type constraints
pub struct AggregateTypes {
    /// A map of pointers to aggregate type constraints
    // XXX: Check if this makes sense for constraints on constants
    constraints: UnorderedMap<Variable, AggrType>,
    /// The co-location constraints from which these size-of constraints have been discovered
    colocated: Rc<CoLocated>,
}

impl std::fmt::Debug for AggregateTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("AggregateTypes")
            .field("constraints", &self.constraints)
            .finish_non_exhaustive()
    }
}

impl AggregateTypes {
    /// Analyze the given `colocated` constraints, and recover aggregate type information
    pub fn analyze(colocated: &Rc<CoLocated>) -> Self {
        let mut constraints: UnorderedMap<Variable, SquishySize> = Default::default();

        for v in colocated.get_aggregate_base_variables().into_iter() {
            constraints.insert(v, SquishySize::new());
        }

        let size_t: usize = colocated.structural_types.ssa.program.pointer_size;

        for (constraint, _reason) in colocated.constraints.iter() {
            match constraint {
                Constraint::OffsetDeref {
                    t,
                    offset,
                    base_ptr,
                } => {
                    if *offset < 0 {
                        constraints
                            .get_mut(base_ptr)
                            .unwrap()
                            .negative_offsets_observed = true;
                    } else {
                        if let Some(size) = colocated
                            .structural_types
                            .get_type_of(t)
                            .unwrap()
                            .observed_size()
                        {
                            if let Some(v) = constraints.get_mut(base_ptr) {
                                v.constrain((*offset).try_into().unwrap(), size);
                            }
                        } else if !matches!(t, Variable::ValueIrrelevantConstant) {
                            // If `t` is a constant, we don't know a size for it. If it is not a
                            // constant, we should have gotten a size.
                            //
                            // XXX: Introduce size information to constants within `Program::infer_structural_types`
                            debug!(
                                "No size found for type of dereferenced value at static offset from base pointer";
                                "t" => ?t,
                                "offset" => offset,
                                "base_ptr" => ?base_ptr,
                            );
                        }
                    }
                }
                Constraint::NonConstantOffsetDeref {
                    t,
                    offset,
                    base_ptr,
                } => {
                    let offset_observed_size = colocated
                        .structural_types
                        .get_type_of(offset)
                        .unwrap()
                        .observed_size();
                    if offset_observed_size != Some(size_t) {
                        debug!(
                            "Non size_t offset found";
                            "offset_type" => ?colocated
                                .structural_types
                                .get_type_of(offset)
                                .unwrap(),
                            "constraint" => ?constraint,
                            "size_t" => size_t,
                            "offset_observed_size" => ?offset_observed_size,
                        );
                    }
                    let v = constraints.get_mut(base_ptr).unwrap();
                    v.non_constant_access = true;
                    if let Some(size) = colocated
                        .structural_types
                        .get_type_of(t)
                        .unwrap()
                        .observed_size()
                    {
                        v.constrain(0, size);
                    } else if *t == Variable::ValueIrrelevantConstant {
                        // Clearly, we can do nothing here at the moment
                    } else {
                        // XXX: Introduce size information to constants within `Program::infer_structural_types`
                        debug!(
                            "No size found for type of dereferenced value at dynamic offset from base pointer";
                            "t" => ?t,
                            "offset" => ?offset,
                            "base_ptr" => ?base_ptr,
                        );
                    }
                }
            }
        }

        Self {
            constraints: constraints
                .into_iter()
                .filter_map(|(k, v)| Some((k, v.to_c_like_type()?)))
                .collect(),
            colocated: colocated.clone(),
        }
    }

    /// Use the recovered aggregate type information to produce structural types that include
    /// aggregate types.
    pub fn to_structural_types(&self) -> StructuralTypes {
        let mut r = self.colocated.structural_types.deep_clone();
        for (ptr, aggrtype) in self.constraints.iter() {
            if matches!(ptr, Variable::ConstantValue { .. }) {
                info!("TODO: Constant as pointer"; "ptr" => ?ptr);
                continue;
            }
            match aggrtype {
                AggrType::Struct {
                    member_sizes,
                    has_unsized_array_at_end,
                } => {
                    if member_sizes.is_empty() {
                        info!("TODO: Invalid member_sizes. Is empty."; "ptr" => ?ptr);
                    } else {
                        r.convert_to_struct(
                            r.get_type_of(ptr).unwrap().pointer_to.unwrap(),
                            member_sizes.iter().cloned(),
                            *has_unsized_array_at_end,
                        );
                    }
                }
                AggrType::Array { member_size } => {
                    r.convert_to_array(
                        r.get_type_of(ptr).unwrap().pointer_to.unwrap(),
                        *member_size,
                    );
                }
            }
        }
        for (constraint, _reason) in self.colocated.constraints.iter() {
            match constraint {
                Constraint::OffsetDeref {
                    t,
                    offset,
                    base_ptr,
                } => {
                    if !self.constraints.contains_key(base_ptr) {
                        continue;
                    }
                    if matches!(base_ptr, Variable::ConstantValue { .. }) {
                        info!(
                            "TODO: Constant as base pointer for offset deref";
                            "base_ptr" => ?base_ptr,
                        );
                        continue;
                    }
                    assert!(*offset >= 0);
                    if *offset == 0 {
                        // XXX: Is this reasonable?
                        continue;
                    }

                    let offset: NonZeroUsize =
                        NonZeroUsize::new((*offset).try_into().unwrap()).unwrap();

                    let t_tyidx = r.get_type_index(t.clone()).unwrap();
                    let b_tyidx = r.get_type_of(base_ptr).unwrap().pointer_to.unwrap();
                    let o_tyidx = r
                        .get_type_from_index(b_tyidx)
                        .unwrap()
                        .colocated_struct_fields
                        .get(&offset);

                    if let Some(&o_tyidx) = o_tyidx {
                        r.mark_types_as_equal(t_tyidx, o_tyidx);
                    } else {
                        debug!(
                            "Could not find colocated struct field with offset \
                             in type of base-pointer";
                            "offset" => ?offset,
                            "base_ptr" => ?base_ptr,
                            "base_ptr_type" => ?r.get_type_of(base_ptr).unwrap(),
                            "base_ptr_pointee_type" => ?r.get_type_from_index(b_tyidx).unwrap(),
                        );
                    }
                }
                Constraint::NonConstantOffsetDeref {
                    t,
                    offset: _,
                    base_ptr,
                } => {
                    if !self.constraints.contains_key(base_ptr) {
                        continue;
                    }
                    if matches!(base_ptr, Variable::ConstantValue { .. }) {
                        info!(
                            "TODO: Constant as base pointer for non-constant offset deref";
                            "base_ptr" => ?base_ptr,
                        );
                        continue;
                    }

                    let t_tyidx = r.get_type_index(t.clone()).unwrap();
                    let b_tyidx = r.get_type_of(base_ptr).unwrap().pointer_to.unwrap();
                    let b_ty = r.get_type_from_index(b_tyidx).unwrap();
                    let o_tyidx = match (
                        b_ty.observed_array,
                        b_ty.colocated_struct_fields.iter().rev().next(),
                    ) {
                        // Note: this assumes `colocated_struct_fields` is an ordmap
                        (false, Some((_size, idx))) => *idx,
                        (true, None) => b_tyidx,
                        (true, Some((_size, idx))) => {
                            debug!(
                                "NonConstantOffsetDeref constraint on base that is array and struct. \
                                 Unclear implications. \
                                 Using last field as array.";
                                "t" => ?t,
                                "base_ptr" => ?base_ptr,
                                "t_ty" => ?r.get_type_of(t),
                                "b_ty" => ?b_ty,
                            );
                            *idx
                        }
                        (false, None) => {
                            debug!(
                                "TODO: Non array being used as array? Unclear implications.";
                                "t" => ?t,
                                "base_ptr" => ?base_ptr,
                                "t_ty" => ?r.get_type_of(t),
                                "b_ty" => ?b_ty,
                            );
                            b_tyidx
                        }
                    };

                    r.mark_types_as_equal(t_tyidx, o_tyidx);
                }
            }
        }
        r.canonicalize_indexes();
        r
    }
}
