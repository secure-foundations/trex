//! A pass that "rounds up" [`StructuralTypes`] to provided set of known primitive types.

use std::collections::BTreeSet;

use crate::c_types;
use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::inference_config::CONFIG;
use crate::joinable_container::{Container, IndexMap, Joinable};
use crate::log::*;
use crate::structural::{BooleanOp, FloatOp, IntegerOp, StructuralType};

/// Perform a rounding up on structural types to C types. Convenience wrapper around [`round_up`]
/// which gives more control.
pub fn round_up_to_c_types(stypes: &mut Container<StructuralType>) {
    let (c_types_names, c_types): (Vec<_>, Vec<_>) =
        c_types::structural_types_for_all_primitive_c_types()
            .into_iter()
            .unzip();

    let rounding = round_up(stypes, &c_types, &c_types_names);
    for (idx, (stype, hm)) in rounding.into_iter() {
        trace!("Rounding type";
                    "union_of" => ?hm.iter()
                        .map(|ri| ri.to_string())
                        .collect::<Vec<_>>(),
                    "new_type" => ?stype,
                    "old_type" => ?stypes.get(idx),
                    "idx" => ?idx,
        );

        let stype = if CONFIG.round_up_undefined_n_to_integer {
            use c_types::BuiltIn::*;
            // A map from undefined to the most likely C integer-like type at that size.
            let undefineds_map = [
                (Undefined1, Char),
                (Undefined2, Short),
                (Undefined4, Int),
                (Undefined8, ULong),
            ]
            .into_iter()
            .collect::<UnorderedMap<_, _>>();
            if hm.len() == 1 {
                match hm.iter().next().unwrap() {
                    RoundedIdx::Padding(_) => {
                        // do nothing
                        stype
                    }
                    RoundedIdx::Primitive(_, name) => {
                        if let Some(key) = undefineds_map
                            .keys()
                            .find(|ud| *name == format!("{:?}", ud))
                        {
                            let value = undefineds_map.get(key).unwrap();
                            let value_tn = format!("{:?}", value);
                            c_types[c_types_names.iter().position(|it| *it == value_tn).unwrap()]
                                .clone()
                        } else {
                            // do nothing
                            stype
                        }
                    }
                }
            } else {
                // do nothing
                stype
            }
        } else {
            // do nothing
            stype
        };

        let stype = if CONFIG.collapse_union_of_signed_and_unsigned_ints {
            use c_types::BuiltIn::*;
            // A map from signed/unsigned integers to their counter-parts, to force a collapse
            // whenever the type is an exact union of the two.
            //
            // The specific ordering of from/to is picked based off of which of the two types is
            // more commonly used by C programmers.
            let counterparts_map = [
                (UChar, Char),
                (ShortShort, UShortShort),
                (UShort, Short),
                (Uint, Int),
                (Long, ULong),
            ]
            .into_iter()
            .collect::<UnorderedMap<_, _>>();
            let counterparts_map_strs = counterparts_map
                .iter()
                .map(|(k, v)| (format!("{:?}", k), format!("{:?}", v)))
                .collect::<UnorderedMap<_, _>>();
            if hm.len() == 2 {
                let hm: Vec<_> = hm
                    .iter()
                    .filter_map(|ri| match ri {
                        RoundedIdx::Primitive(_, name) => Some(name),
                        RoundedIdx::Padding(_) => None,
                    })
                    .filter(|&name| {
                        counterparts_map.keys().any(|c| *name == format!("{:?}", c))
                            || counterparts_map
                                .values()
                                .any(|c| *name == format!("{:?}", c))
                    })
                    .collect();
                if hm.len() == 2 {
                    if counterparts_map_strs.contains_key(*hm[0])
                        && hm[1] == counterparts_map_strs.get(*hm[0]).unwrap()
                    {
                        // first one is "from", second is "to"
                        c_types[c_types_names.iter().position(|it| it == hm[1]).unwrap()].clone()
                    } else if counterparts_map_strs.contains_key(*hm[1])
                        && hm[0] == counterparts_map_strs.get(*hm[1]).unwrap()
                    {
                        // second one is "from", first is "to"
                        c_types[c_types_names.iter().position(|it| it == hm[0]).unwrap()].clone()
                    } else {
                        // do nothing
                        stype
                    }
                } else {
                    // do nothing
                    stype
                }
            } else {
                // do nothing
                stype
            }
        } else {
            // do nothing
            stype
        };

        *stypes.get_mut(idx) = stype;
    }
}

/// Round single union-of-C-primitives structural type up to C types. This is a convenience wrapper
/// around [`round_up`]. You probably want [`round_up_to_c_types`] instead though.
pub fn recognize_union_of_c_primitives(stype: &StructuralType) -> Option<BTreeSet<String>> {
    let (c_types_names, c_types): (Vec<_>, Vec<_>) =
        c_types::structural_types_for_all_primitive_c_types()
            .into_iter()
            .unzip();

    if stype.refers_to().count() > 0 {
        // This function only allows union-of-c-primitives, so can't have any references to things.
        return None;
    }

    let mut stypes = Container::new();
    let idx = stypes.insert(stype.clone());

    let rounding = round_up(&stypes, &c_types, &c_types_names);
    let (_rounded_stype, unioned) = rounding.get(idx).unwrap();

    let mut res = BTreeSet::new();
    for ridx in unioned {
        res.insert(ridx.to_string());
    }
    Some(res)
}

/// Indices to rounded types
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RoundedIdx<'a> {
    /// Regular primitive, indexing into the `allowed_primitives` list
    ///
    /// The name of the type is included for easier debugging.
    Primitive(usize, &'a str),
    /// Padding bytes, representing the number of bytes; used only if regular primitives are
    /// insufficient to express the rounded type
    Padding(usize),
}
impl<'a> std::fmt::Display for RoundedIdx<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RoundedIdx::Primitive(_idx, name) => write!(f, "{}", name),
            RoundedIdx::Padding(bytes) => write!(f, "padding[{}]", bytes),
        }
    }
}

/// Perform minimal "rounding up" of the structural types in `stypes`, such that all primitives in
/// it are either those provided in `allowed_primitives`, or are unions of them.
///
/// The return type is a map from indexes in `stypes` to a rounded-up structural type and sets of
/// indexes into `allowed_primitives`, which specify which primitives need to be union'd together to
/// get the necessary primitive.
pub fn round_up<'a>(
    stypes: &Container<StructuralType>,
    allowed_primitives: &[StructuralType],
    allowed_primitives_names: &'a [impl AsRef<str>],
) -> IndexMap<(StructuralType, UnorderedSet<RoundedIdx<'a>>)> {
    // Check that `allowed_primitives` are all actually primitives
    allowed_primitives.iter().for_each(assert_is_primitive);

    // This method uses matrix inversion and multiplication to find the minimal rounding for each
    // given structural type.
    //
    // The approach:
    //
    // Let `matrix_a` be the `allowed_primitives` converted to a matrix. Each row is
    // the allowed primitive index, while each column is a capability in the capability vector
    // space (thus, let it have dimensions say NxC).
    //
    // Let `vector_b` be the capability vector (i.e., it equivalent to a 1xC row vector matrix)
    // corresponding to a particular structural type, say `S`.
    //
    // Let `vector_x` be a vector of 1s and 0s, representing which of the allowed primitives should
    // be selected (i.e., it is equivalent to a 1xN row vector matrix).
    //
    // Then, if we take the union of all those primitives selected by `vector_x`, this is equivalent
    // to the matrix multiplication `vector_x * matrix_a`. For consistency of types (i.e., so that
    // we are only rounding upwards), this union must be a superset of `vector_b`.
    //
    // Said differently, `vector_x * matrix_a >= vector_b`, where we consider the inequality to be
    // element-wise on the vectors.
    //
    // The minimum such `vector_x` must thus satisfy `vector_x * matrix_a == vector_b`. (??? Is this
    // a reasonable mathematical statement ???)
    //
    // Thus we can compute `vector_x` simply using `vector_b * matrix_a^{-1}`, if the inverse of
    // `matrix_a` exists. Since `matrix_a` is not (necessarily) square, we cannot use regular
    // inverses, but instead must use generalized inverses. Alternatively, we can use an LP solver
    // (eg: simplex algorithm to solve the linear programming problem); alternatively, we can use
    // some sort of MAX-SAT (although we probably need it flipped around to MIN mode?).

    // The current implementation does something more convenient (although not necessarily
    // optimal). It uses a greedy algorithm to find a valid set of unions. It does this by starting
    // off each type by a union of all allowed primitives, and repeatedly subtracting out the "most
    // expensive" primitive (i.e. the primitive with the maximum number of "on" bits in the
    // capability vector), leaving it only with a set of primitives that are essential to the union.
    //
    // Since the matrix has very few overlaps, we would not expect this to differ too far from
    // optimality.

    let matrix_a = allowed_primitives
        .iter()
        .map(CapabilityVec::from_structural_type)
        .collect::<Vec<CapabilityVec>>();

    let expensiveness_sort: Vec<usize> = {
        let mut v = (0usize..allowed_primitives.len()).collect::<Vec<_>>();
        v.sort_unstable_by(|&i, &j| matrix_a[i].compare_expensiveness_to(&matrix_a[j]));
        // [cheapest, ..... expensivest]
        v
    };

    let initial_vec: CapabilityVec = matrix_a
        .iter()
        .cloned()
        .reduce(|accum, val| accum.add(&val))
        .expect("At least one allowed primitive exists");

    let mut ret: IndexMap<(StructuralType, UnorderedSet<RoundedIdx>)> = Default::default();

    for idx in stypes.currently_alive_canon_indices_iter() {
        let stype = stypes.get(idx);
        let capvec = CapabilityVec::from_structural_type(stype);
        let mut roundedvec: CapabilityVec = initial_vec.clone();
        ret.insert(idx, (stype.clone(), UnorderedSet::new()));

        let mut capvec = capvec;
        if !capvec.is_smaller_type_than(&initial_vec) {
            {
                let capvec_sizes: UnorderedSet<_> = capvec.cap_copy_sizes.keys().cloned().collect();
                let initvec_sizes: UnorderedSet<_> =
                    initial_vec.cap_copy_sizes.keys().cloned().collect();

                let extra_sizes = &capvec_sizes - &initvec_sizes;
                trace!(
                    "Found padding copy sizes";
                    "initvec_sizes" => ?initvec_sizes,
                    "capvec_sizes" => ?capvec_sizes,
                    "extra_sizes" => ?extra_sizes,
                );
                for sz in extra_sizes {
                    ret.get_mut(idx).unwrap().1.insert(RoundedIdx::Padding(sz));
                    capvec.cap_copy_sizes.remove(&sz);
                }
            }

            {
                let capvec_sizes: UnorderedSet<_> =
                    capvec.cap_upper_bound_sizes.keys().cloned().collect();
                let initvec_sizes: UnorderedSet<_> =
                    initial_vec.cap_upper_bound_sizes.keys().cloned().collect();

                let extra_sizes = &capvec_sizes - &initvec_sizes;
                trace!(
                    "Found padding upper-bound sizes";
                    "initvec_sizes" => ?initvec_sizes,
                    "capvec_sizes" => ?capvec_sizes,
                    "extra_sizes" => ?extra_sizes,
                );
                for sz in extra_sizes {
                    ret.get_mut(idx).unwrap().1.insert(RoundedIdx::Padding(sz));
                    capvec.cap_upper_bound_sizes.remove(&sz);
                }
            }

            if !capvec.is_smaller_type_than(&initial_vec) {
                debug!(
                    "Union of primitives is not universe";
                    "reason" => capvec.reason_not_smaller_type_than(&initial_vec).unwrap(),
                    "stype" => ?stype,
                    "idx" => ?idx,
                );
            }
        }
        let capvec = capvec;

        trace!("Rounding"; "capvec" => ?capvec, "stype" => ?stype, "idx" => ?idx);
        for &i in expensiveness_sort.iter().rev() {
            // TODO: This can probably be cleaned up by subtracting out `capvec` from the
            // `initial_vec` early on before the loop?
            let (is_deletable, newvec) = if let Some(newvec) = roundedvec.sub(&matrix_a[i]) {
                (capvec.is_smaller_type_than(&newvec), newvec)
            } else {
                (false, roundedvec.clone())
            };

            if is_deletable {
                trace!(
                    "Deleted";
                    "prim" => allowed_primitives_names[i].as_ref(),
                );
                roundedvec = newvec;
            } else {
                trace!(
                    "Non deletable";
                    "prim" => allowed_primitives_names[i].as_ref(),
                    "reason" => capvec.reason_not_smaller_type_than(&newvec).unwrap(),
                );
                ret.get_mut(idx).unwrap().1.insert(RoundedIdx::Primitive(
                    i,
                    allowed_primitives_names[i].as_ref(),
                ));
            }
        }
        trace!(
            "Rounded";
            "prims" => ?ret.get(idx).unwrap().1.iter().map(|ri| ri.to_string()).collect::<Vec<_>>()
        );
        if roundedvec.cap_is_pointer > 0 && stypes.get(idx).pointer_to.is_none() {
            debug!(
                "Pointerness inconsistency in rounding";
                "prims" => ?ret.get(idx).unwrap().1.iter().map(|ri| ri.to_string()).collect::<Vec<_>>(),
                "stype" => ?stype,
                "idx" => ?idx,
            );
        }

        roundedvec
            .normalize()
            .apply_to_structural_type(&mut ret.get_mut(idx).unwrap().0);
    }

    ret
}

#[cfg(test)]
mod test {
    use super::{assert_is_primitive, round_up, CapabilityVec};
    use crate::joinable_container::{Container, Index};
    use crate::structural::StructuralType;
    use std::collections::BTreeMap;

    #[test]
    fn primitives_are_all_actually_primitive() {
        let allowed_primitives: &[StructuralType] =
            &crate::c_types::structural_types_for_all_primitive_c_types()
                .into_iter()
                .map(|x| x.1)
                .collect::<Vec<_>>();
        allowed_primitives.iter().for_each(assert_is_primitive);
    }

    #[test]
    fn primitives_round_to_themselves() {
        let (primitives_names, primitives): (Vec<String>, Vec<StructuralType>) =
            crate::c_types::structural_types_for_all_primitive_c_types()
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .unzip();
        dbg!(&primitives_names);
        let mut container = Container::new();
        let mut type_map: Vec<Index> = Default::default();
        for prim in primitives.iter() {
            type_map.push(container.insert(prim.clone()));
        }
        let res = round_up(&container, &primitives, &primitives_names);
        for (name, idx) in primitives_names.iter().zip(type_map.iter().cloned()) {
            let (new_styp, merge) = res.get(idx).unwrap();
            if name != "Void" {
                assert_eq!(
                    merge
                        .into_iter()
                        .map(|ri| ri.to_string())
                        .collect::<Vec<String>>(),
                    vec![name.clone()],
                );
            }
            assert_eq!(
                CapabilityVec::from_structural_type(new_styp),
                CapabilityVec::from_structural_type(container.get(idx)),
                "Failed on {name}",
            );
        }
    }

    #[test]
    fn only_one_pointer_in_primitive() {
        let (primitives_names, primitives): (Vec<String>, Vec<StructuralType>) =
            crate::c_types::structural_types_for_all_primitive_c_types()
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .unzip();
        dbg!(&primitives_names);
        assert_eq!(
            primitives
                .into_iter()
                .filter(|st| st.pointer_to.is_some())
                .count(),
            1
        );
    }
}

/// A representation of the capabilities of a `StructuralType`, to aid in computation of
/// [`round_up`]. A consistent rounded type would be one where
/// `rounded_type.is_smaller_than(original_type)`.
///
/// Note: This type stores more information than absolutely necessary for the high-level consistency
/// result. It does so in order to aid in the greedy algorithm in [`round_up`] during its
/// computation. Call [`Self::normalize`] to obtain a normalized representation.
#[derive(Clone, PartialEq, Eq, Debug)]
struct CapabilityVec {
    cap_is_pointer: u64,
    cap_is_code: u64,
    cap_zero_comparable: u64,
    cap_observed_boolean: u64,
    cap_upper_bound_sizes: UnorderedMap<usize, u64>,
    cap_copy_sizes: UnorderedMap<usize, u64>,
    cap_integer_ops: UnorderedMap<(IntegerOp, usize), u64>,
    cap_boolean_ops: UnorderedMap<(BooleanOp, usize), u64>,
    cap_float_ops: UnorderedMap<(FloatOp, usize), u64>,
}

impl CapabilityVec {
    /// Returns `true` iff `self`s capabilities are a (non-strict) subset of the capabilities of
    /// `other`.
    fn is_smaller_type_than(&self, other: &Self) -> bool {
        self.reason_not_smaller_type_than(other).is_none()
    }

    /// Returns the reason `self`'s capabilities are not a (non-strict) subset of the capabilities of
    /// `other`. If they are indeed a (non-strict) subset of the capabilties, returns `None`
    fn reason_not_smaller_type_than(&self, other: &Self) -> Option<String> {
        let Self {
            cap_is_pointer,
            cap_is_code,
            cap_zero_comparable,
            cap_observed_boolean,
            cap_upper_bound_sizes,
            cap_copy_sizes,
            cap_integer_ops,
            cap_boolean_ops,
            cap_float_ops,
        } = self;

        fn mapfail<T: std::fmt::Debug + Eq + std::hash::Hash + Ord>(
            t: &'static str,
            x: &UnorderedMap<T, u64>,
            y: &UnorderedMap<T, u64>,
        ) -> Option<String> {
            let mut res = vec![];
            for (k, count) in x.iter() {
                if count > y.get(k).unwrap_or(&0) {
                    res.push(k);
                }
            }
            if res.is_empty() {
                None
            } else {
                Some(format!("{:?} in {}", res, t))
            }
        }

        if *cap_is_pointer > other.cap_is_pointer {
            return Some("cap_is_pointer".into());
        }
        if *cap_is_code > other.cap_is_code {
            return Some("cap_is_code".into());
        }
        if *cap_zero_comparable > other.cap_zero_comparable {
            return Some("cap_zero_comparable".into());
        }
        if *cap_observed_boolean > other.cap_observed_boolean {
            return Some("cap_observed_boolean".into());
        }
        if let Some(reason) = mapfail(
            "cap_upper_bound_sizes",
            cap_upper_bound_sizes,
            &other.cap_upper_bound_sizes,
        ) {
            return Some(reason);
        }
        if let Some(reason) = mapfail("cap_copy_sizes", cap_copy_sizes, &other.cap_copy_sizes) {
            return Some(reason);
        }
        if let Some(reason) = mapfail("cap_integer_ops", cap_integer_ops, &other.cap_integer_ops) {
            return Some(reason);
        }
        if let Some(reason) = mapfail("cap_boolean_ops", cap_boolean_ops, &other.cap_boolean_ops) {
            return Some(reason);
        }
        if let Some(reason) = mapfail("cap_float_ops", cap_float_ops, &other.cap_float_ops) {
            return Some(reason);
        }

        None
    }

    /// Returns the ordering of `self` compared to `rhs`, in terms of expensiveness. More expensive
    /// capvecs are deleted sooner than less expensive ones.
    fn compare_expensiveness_to(&self, rhs: &Self) -> std::cmp::Ordering {
        let Self {
            cap_is_pointer,
            cap_is_code,
            cap_zero_comparable,
            cap_observed_boolean,
            cap_upper_bound_sizes,
            cap_copy_sizes,
            cap_integer_ops,
            cap_boolean_ops,
            cap_float_ops,
        } = self;

        fn mapcmp<T: std::hash::Hash + Ord>(
            x: &UnorderedMap<T, u64>,
            y: &UnorderedMap<T, u64>,
        ) -> std::cmp::Ordering {
            let x = x.values().filter(|&&v| v > 0).count();
            let y = y.values().filter(|&&v| v > 0).count();
            x.cmp(&y)
        }

        let mut res = std::cmp::Ordering::Equal;
        res = res.then(cap_is_pointer.cmp(&rhs.cap_is_pointer));
        res = res.then(cap_is_code.cmp(&rhs.cap_is_code));

        if CONFIG.prefer_signed_integers_when_rounding {
            let unsigned_ops: UnorderedSet<_> = IntegerOp::unsigned_ops().into_iter().collect();
            res = res.then_with(|| {
                mapcmp(
                    &cap_integer_ops
                        .iter()
                        .filter(|((op, _), _)| unsigned_ops.contains(op))
                        .map(|((op, sz), count)| ((*op, *sz), *count))
                        .collect(),
                    &rhs.cap_integer_ops
                        .iter()
                        .filter(|((op, _), _)| unsigned_ops.contains(op))
                        .map(|((op, sz), count)| ((*op, *sz), *count))
                        .collect(),
                )
            });
        }

        // XXX: Maybe we should be taking sums of sizes?
        res = res.then(cap_zero_comparable.cmp(&rhs.cap_zero_comparable));
        res = res.then(cap_observed_boolean.cmp(&rhs.cap_observed_boolean));
        res = res.then_with(|| mapcmp(cap_upper_bound_sizes, &rhs.cap_upper_bound_sizes));
        res = res.then_with(|| mapcmp(cap_copy_sizes, &rhs.cap_copy_sizes));
        res = res.then_with(|| mapcmp(cap_integer_ops, &rhs.cap_integer_ops));
        res = res.then_with(|| mapcmp(cap_boolean_ops, &rhs.cap_boolean_ops));
        res = res.then_with(|| mapcmp(cap_float_ops, &rhs.cap_float_ops));
        res
    }

    /// Add in capabilities of `self` and `other`. This will often lead to a non-normalized
    /// representation.
    #[must_use]
    fn add(&self, other: &Self) -> Self {
        fn mapadd<T: Clone + Eq + std::hash::Hash + Ord>(
            x: &UnorderedMap<T, u64>,
            y: &UnorderedMap<T, u64>,
        ) -> UnorderedMap<T, u64> {
            let mut ret: UnorderedMap<T, u64> = x.clone();
            for (k, v) in y.iter() {
                *ret.entry(k.clone()).or_insert(0) += v;
            }
            ret
        }

        Self {
            cap_is_pointer: self.cap_is_pointer + other.cap_is_pointer,
            cap_is_code: self.cap_is_code + other.cap_is_code,
            cap_zero_comparable: self.cap_zero_comparable + other.cap_zero_comparable,
            cap_observed_boolean: self.cap_observed_boolean + other.cap_observed_boolean,
            cap_upper_bound_sizes: mapadd(
                &self.cap_upper_bound_sizes,
                &other.cap_upper_bound_sizes,
            ),
            cap_copy_sizes: mapadd(&self.cap_copy_sizes, &other.cap_copy_sizes),
            cap_integer_ops: mapadd(&self.cap_integer_ops, &other.cap_integer_ops),
            cap_boolean_ops: mapadd(&self.cap_boolean_ops, &other.cap_boolean_ops),
            cap_float_ops: mapadd(&self.cap_float_ops, &other.cap_float_ops),
        }
    }

    /// Subtract capabilities of `rhs` from `self`. This will often lead to a non-normalized
    /// representation. If the subtraction leads to an invalid representation, `None` is returned.
    #[must_use]
    fn sub(&self, rhs: &Self) -> Option<Self> {
        fn mapsub<T: Clone + Eq + std::hash::Hash + Ord>(
            x: &UnorderedMap<T, u64>,
            y: &UnorderedMap<T, u64>,
        ) -> UnorderedMap<T, u64> {
            let mut ret = x.clone();
            for (k, v) in y.iter() {
                *ret.get_mut(k).unwrap() -= v;
            }
            ret
        }

        if rhs.is_smaller_type_than(self) {
            Some(Self {
                cap_is_pointer: self.cap_is_pointer - rhs.cap_is_pointer,
                cap_is_code: self.cap_is_code - rhs.cap_is_code,
                cap_zero_comparable: self.cap_zero_comparable - rhs.cap_zero_comparable,
                cap_observed_boolean: self.cap_observed_boolean - rhs.cap_observed_boolean,
                cap_upper_bound_sizes: mapsub(
                    &self.cap_upper_bound_sizes,
                    &rhs.cap_upper_bound_sizes,
                ),
                cap_copy_sizes: mapsub(&self.cap_copy_sizes, &rhs.cap_copy_sizes),
                cap_integer_ops: mapsub(&self.cap_integer_ops, &rhs.cap_integer_ops),
                cap_boolean_ops: mapsub(&self.cap_boolean_ops, &rhs.cap_boolean_ops),
                cap_float_ops: mapsub(&self.cap_float_ops, &rhs.cap_float_ops),
            })
        } else {
            None
        }
    }

    /// Normalize to a standard representation. See the note in top-level documentation of [`Self`]
    /// for more details.
    #[must_use]
    fn normalize(&self) -> Self {
        fn mapnorm<T: Clone + Eq + std::hash::Hash + Ord>(
            x: &UnorderedMap<T, u64>,
        ) -> UnorderedMap<T, u64> {
            let mut ret: UnorderedMap<T, u64> = Default::default();
            for (k, &v) in x {
                if v > 0 {
                    ret.insert(k.clone(), 1);
                }
            }
            ret
        }
        if !CONFIG.allow_type_rounding_based_on_upper_bound_size {
            assert!(self.cap_upper_bound_sizes.is_empty());
        }
        Self {
            cap_is_pointer: self.cap_is_pointer.min(1),
            cap_is_code: self.cap_is_code.min(1),
            cap_zero_comparable: self.cap_zero_comparable.min(1),
            cap_observed_boolean: self.cap_observed_boolean.min(1),
            cap_upper_bound_sizes: mapnorm(&self.cap_upper_bound_sizes),
            cap_copy_sizes: mapnorm(&self.cap_copy_sizes),
            cap_integer_ops: mapnorm(&self.cap_integer_ops),
            cap_boolean_ops: mapnorm(&self.cap_boolean_ops),
            cap_float_ops: mapnorm(&self.cap_float_ops),
        }
    }

    /// Convert from a structural type `stype` to a capability vector. Guaranteed to be normalized.
    fn from_structural_type(stype: &StructuralType) -> Self {
        // NOTE: Must be kept in sync with `Self::apply_to_structural_type`

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
            colocated_struct_fields: _,
            observed_array: _,
            is_type_for_il_constant_variable: _,
        } = stype;

        let mut ubs_map: UnorderedMap<usize, u64> = Default::default();
        if CONFIG.allow_type_rounding_based_on_upper_bound_size {
            if let Some(size) = upper_bound_size {
                let prev = ubs_map.insert(*size, 1);
                assert_eq!(prev, None);
            }
        }
        let mut cs_map: UnorderedMap<usize, u64> = Default::default();
        for size in copy_sizes {
            let prev = cs_map.insert(*size, 1);
            assert_eq!(prev, None);
        }

        let mut io_map: UnorderedMap<(IntegerOp, usize), u64> = Default::default();
        for (op, size) in integer_ops.iter().cloned() {
            io_map.insert((op, size), 1);
        }
        let mut bo_map: UnorderedMap<(BooleanOp, usize), u64> = Default::default();
        for (op, size) in boolean_ops.iter().cloned() {
            bo_map.insert((op, size), 1);
        }
        let mut fo_map: UnorderedMap<(FloatOp, usize), u64> = Default::default();
        for (op, size) in float_ops.iter().cloned() {
            fo_map.insert((op, size), 1);
        }

        Self {
            cap_is_pointer: pointer_to.is_some() as _,
            cap_is_code: *observed_code as _,
            cap_zero_comparable: *zero_comparable as _,
            cap_observed_boolean: *observed_boolean as _,
            cap_upper_bound_sizes: ubs_map,
            cap_copy_sizes: cs_map,
            cap_integer_ops: io_map,
            cap_boolean_ops: bo_map,
            cap_float_ops: fo_map,
        }
    }

    /// Apply `self`'s capabilities to the structural type `stype`
    fn apply_to_structural_type(&self, stype: &mut StructuralType) {
        // NOTE: Must be kept in sync with `Self::from_structural_type`

        let Self {
            cap_is_pointer,
            cap_is_code,
            cap_zero_comparable,
            cap_observed_boolean,
            cap_upper_bound_sizes,
            cap_copy_sizes,
            cap_integer_ops,
            cap_boolean_ops,
            cap_float_ops,
        } = self;

        let original_stype = stype.clone();

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
            colocated_struct_fields: _,
            observed_array: _,
            is_type_for_il_constant_variable: _,
        } = stype;

        for (&sz, &v) in cap_upper_bound_sizes.iter() {
            assert_eq!(v, 1);
            if let Some(ubs) = *upper_bound_size {
                if ubs != sz {
                    debug!("Got non-equal upper bound size";
                          "in_type" => ubs, "in_vec" => sz);
                }
            } else {
                *upper_bound_size = Some(sz);
            }
        }
        for (&sz, &v) in cap_copy_sizes.iter() {
            assert_eq!(v, 1);
            copy_sizes.insert(sz);
        }

        for (&os, &v) in cap_integer_ops.iter() {
            assert_eq!(v, 1);
            integer_ops.insert(os);
        }
        for (&os, &v) in cap_boolean_ops.iter() {
            assert_eq!(v, 1);
            boolean_ops.insert(os);
        }
        for (&os, &v) in cap_float_ops.iter() {
            assert_eq!(v, 1);
            float_ops.insert(os);
        }

        if *cap_is_pointer > 0 {
            if pointer_to.is_none() {
                crit!("Pointerness failure"; "capability" => ?self, "stype" => ?original_stype);
                panic!(
                    "Pointerness failure. Original stype: {:?}. Full capability: {:?}.",
                    original_stype, self
                );
            }
        }
        if *cap_zero_comparable > 0 {
            *zero_comparable = true;
        }
        if *cap_observed_boolean > 0 {
            *observed_boolean = true;
        }
        if *cap_is_code > 0 {
            *observed_code = true;
        }
    }
}

fn assert_is_primitive(stype: &StructuralType) {
    let StructuralType {
        upper_bound_size: _,
        copy_sizes: _,
        zero_comparable: _,
        pointer_to: _,
        observed_boolean: _,
        integer_ops: _,
        boolean_ops: _,
        float_ops: _,
        observed_code: _,
        colocated_struct_fields,
        observed_array,
        is_type_for_il_constant_variable,
    } = stype;

    if colocated_struct_fields.is_empty() && !observed_array && !is_type_for_il_constant_variable {
        // Do nothing
    } else {
        panic!("Found non-primitive type {:?}", stype)
    }
}

const SPECIAL_SIZES: &[usize] = &[1, 2, 4, 8, 16];
