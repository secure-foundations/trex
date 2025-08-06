//! Representations of C-like types, and their mapping to/from [`structural`](crate::structural)

use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::inference_config::CONFIG;
use crate::joinable_container::{Container, Index};
use crate::log::*;
use crate::structural::{self, BooleanOp, FloatOp, IntegerOp, StructuralType};
use std::collections::VecDeque;

/// C built-ins. Note that the `undefined*` variants within this are not _true_ C built-ins, but
/// instead exist to account for types that have too little information known other than their size.
#[derive(PartialEq, Eq, Debug, Hash, PartialOrd, Ord, Clone)]
pub enum BuiltIn {
    Void,
    Bool,
    Char,
    UChar,
    WCharT,
    /// Not actually a C-type, but `short short int` represents a `signed char` that also has
    /// integer operations occuring on it, rather than only character operations.
    ShortShort,
    /// Not actually a C-type, but `unsigned short short int` represents an `unsigned char` that
    /// also has integer operations occuring on it, rather than only character operations.
    UShortShort,
    Short,
    UShort,
    Int,
    Uint,
    Long,
    ULong,
    /// Not actually a C-type, but represents a signed 128 bit integer
    SInt128,
    /// Not actually a C-type, but represents an unsigned 128 bit integer
    UInt128,
    /// Not actually a C-type, but represents a signed 256 bit integer
    SInt256,
    /// Not actually a C-type, but represents an unsigned 256 bit integer
    UInt256,
    Float,
    Double,
    LongDouble,
    /// An unsized undefined type
    Undefined,
    /// A 1-byte undefined type
    Undefined1,
    /// A 2-byte undefined type
    Undefined2,
    /// A 4-byte undefined type
    Undefined4,
    /// A 8-byte undefined type
    Undefined8,
    // NOTE: Make sure to extend `all_builtins` when this is extended
}

impl BuiltIn {
    /// All built ins. The iterator is guaranteed to produce these in the same order each time
    /// during execution.
    ///
    /// Note: it is possible you are looking for [`structural_types_for_all_primitive_c_types`]
    /// instead.
    pub fn all_builtins() -> impl IntoIterator<Item = Self> {
        use BuiltIn::*;
        [
            Void,
            Bool,
            Char,
            UChar,
            WCharT,
            ShortShort,
            UShortShort,
            Short,
            UShort,
            Int,
            Uint,
            Long,
            ULong,
            SInt128,
            UInt128,
            SInt256,
            UInt256,
            Float,
            Double,
            LongDouble,
            Undefined,
            Undefined1,
            Undefined2,
            Undefined4,
            Undefined8,
        ]
    }

    /// Convert to a printable C name
    pub fn to_printable(&self) -> &str {
        use BuiltIn::*;
        match self {
            Void => "void",
            Bool => "bool",
            Char => "char",
            UChar => "unsigned char",
            WCharT => "wchar_t",
            ShortShort => "int8_t",
            UShortShort => "uint8_t",
            Short => "int16_t",
            UShort => "uint16_t",
            Int => "int32_t",
            Uint => "uint32_t",
            Long => "int64_t",
            ULong => "uint64_t",
            SInt128 => "int128_t",
            UInt128 => "uint128_t",
            SInt256 => "int256_t",
            UInt256 => "uint256_t",
            Float => "float",
            Double => "double",
            LongDouble => "long double",
            Undefined => "undefined",
            Undefined1 => "undefined1",
            Undefined2 => "undefined2",
            Undefined4 => "undefined4",
            Undefined8 => "undefined8",
        }
    }
}

/// A representation of C-like types.
///
/// References to other types are done through naming, thus recursiveness in types is factored out
/// of this particular `enum` and instead needs to be handled by an external container mapping names
/// to `CType`s, specifically [`CTypes`].
#[derive(PartialEq, Eq, Debug)]
pub enum CType {
    /// A built-in type
    BuiltIn(BuiltIn),
    /// A union of all types, specified by name
    Union(Vec<String>),
    /// A structure with fields consisting of each of the given types, specified by field offset and
    /// name
    Struct(Vec<(usize, String)>),
    /// A typedef to the given type
    TypeDef(String),
    /// A pointer to the given type (and also the size of the pointer)
    Pointer(usize, String),
    /// An enumeration, consisting of the size of the type, and the set of allowed values
    Enum(usize, Vec<i32>),
    /// A fixed-size array, consisting of the array element type, size of the element, and number of
    /// elements in the array
    FixedSizeArray(String, usize, usize),
    /// An unsized array, consisting of the array element type
    UnsizedArray(String),
    /// Something executable. A function pointer is thus represented as a pointer to code.
    Code,
}

#[derive(Debug)]
/// Structural types, equivalent to the relevant [`CTypes`] this was converted from.
pub struct STypes {
    /// Names for each structural type
    pub type_map: UnorderedMap<String, Index>,
    /// The structural types themselves
    pub types: Container<StructuralType>,
}

fn set_upper_and_copy_size(this: &mut StructuralType, sz: usize) {
    this.copy_sizes.extend(match sz {
        1 => &[1][..],
        2 => &[1, 2][..],
        4 => &[1, 2, 4][..],
        8 => &[1, 2, 4, 8][..],
        16 => &[1, 2, 4, 8, 16][..],
        32 => &[1, 2, 4, 8, 16, 32][..],
        _ => unreachable!("set_upper_and_copy_size(..., {})", sz),
    });
    this.set_upper_bound_size(sz);
}

pub fn is_undefined_padding(s: &StructuralType) -> bool {
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
    } = s;
    *upper_bound_size == Some(1)
        && copy_sizes.is_empty()
        && !zero_comparable
        && pointer_to.is_none()
        && !observed_boolean
        && integer_ops.is_empty()
        && boolean_ops.is_empty()
        && float_ops.is_empty()
        && !observed_code
        && colocated_struct_fields.is_empty()
        && !observed_array
        && !is_type_for_il_constant_variable
}

pub fn get_undefined_padding() -> StructuralType {
    let mut ret = StructuralType::default();
    ret.set_upper_bound_size(1);
    ret
}

mod test {
    #[test]
    fn undefined_padding_is_undefined_padding() {
        assert!(crate::c_types::is_undefined_padding(
            &crate::c_types::get_undefined_padding()
        ));
    }
}

#[must_use]
// Returns `true` if initialization is completed; `false` if waiting on other types to finish
// initializing first.
fn update_structural(
    ctype: &CType,
    name: &str,
    stypes: &mut STypes,
    completed: &UnorderedSet<String>,
) -> bool {
    let this_idx = *stypes
        .type_map
        .entry(name.into())
        .or_insert_with(|| stypes.types.insert(StructuralType::default()));
    let this = &mut stypes.types[this_idx];
    let success = match ctype {
        CType::BuiltIn(BuiltIn::Void) => {
            // XXX: Is there a different representation that would be better here?
            true
        }
        CType::BuiltIn(BuiltIn::Undefined) => {
            this.set_upper_bound_size(1); // Explicitly not setting copy size here

            // XXX: We should probably explicitly mark this as undefined somehow? Seems to only
            // be used for padding purposes in structs.

            assert!(is_undefined_padding(this));

            true
        }
        CType::BuiltIn(BuiltIn::Undefined1) => {
            set_upper_and_copy_size(this, 1);
            true
        }
        CType::BuiltIn(BuiltIn::Undefined2) => {
            set_upper_and_copy_size(this, 2);
            true
        }
        CType::BuiltIn(BuiltIn::Undefined4) => {
            set_upper_and_copy_size(this, 4);
            true
        }
        CType::BuiltIn(BuiltIn::Undefined8) => {
            set_upper_and_copy_size(this, 8);
            true
        }
        CType::BuiltIn(BuiltIn::Bool) => {
            set_upper_and_copy_size(this, 1);
            this.observed_boolean = true;
            this.zero_comparable = true;
            this.boolean_ops = BooleanOp::all_ops().into_iter().map(|o| (o, 1)).collect();
            true
        }
        CType::BuiltIn(t @ (BuiltIn::Char | BuiltIn::UChar | BuiltIn::WCharT)) => {
            let (is_signed, sz) = match t {
                BuiltIn::Char => (true, 1),
                BuiltIn::UChar => (false, 1),
                BuiltIn::WCharT => (true, 4),
                _ => unreachable!(),
            };
            set_upper_and_copy_size(this, sz);
            this.zero_comparable = true;
            this.integer_ops = IntegerOp::char_ops(is_signed)
                .into_iter()
                .map(|o| (o, sz))
                .collect();
            true
        }
        CType::BuiltIn(
            t @ (BuiltIn::ShortShort
            | BuiltIn::UShortShort
            | BuiltIn::Short
            | BuiltIn::UShort
            | BuiltIn::Int
            | BuiltIn::Uint
            | BuiltIn::Long
            | BuiltIn::ULong
            | BuiltIn::SInt128
            | BuiltIn::UInt128
            | BuiltIn::SInt256
            | BuiltIn::UInt256),
        ) => {
            let (is_signed, sz) = match t {
                BuiltIn::ShortShort => (true, 1),
                BuiltIn::UShortShort => (false, 1),
                BuiltIn::Short => (true, 2),
                BuiltIn::UShort => (false, 2),
                BuiltIn::Int => (true, 4),
                BuiltIn::Uint => (false, 4),
                BuiltIn::Long => (true, 8),
                BuiltIn::ULong => (false, 8),
                BuiltIn::SInt128 => (true, 16),
                BuiltIn::UInt128 => (false, 16),
                BuiltIn::SInt256 => (true, 32),
                BuiltIn::UInt256 => (false, 32),
                _ => unreachable!(),
            };
            set_upper_and_copy_size(this, sz);
            this.zero_comparable = true;
            this.integer_ops = if is_signed {
                let ops: Box<dyn Iterator<Item = IntegerOp>> =
                    if CONFIG.signed_integers_support_all_integer_ops {
                        Box::new(IntegerOp::all_ops().into_iter())
                    } else {
                        Box::new(IntegerOp::signed_ops().into_iter())
                    };
                ops.map(|o| (o, sz))
                    .chain(
                        if CONFIG.additionally_include_next_size_nonlinear_ops_for_integers {
                            vec![
                                (IntegerOp::SDiv, sz * 2),
                                (IntegerOp::SRem, sz * 2),
                                (IntegerOp::Mult, sz * 2),
                            ]
                        } else {
                            vec![]
                        },
                    )
                    .chain(
                        if CONFIG.signed_integers_support_all_integer_ops
                            && CONFIG.additionally_include_next_size_nonlinear_ops_for_integers
                        {
                            vec![(IntegerOp::UDiv, sz * 2), (IntegerOp::URem, sz * 2)]
                        } else {
                            vec![]
                        },
                    )
                    .collect()
            } else {
                IntegerOp::unsigned_ops()
                    .into_iter()
                    .map(|o| (o, sz))
                    .chain(
                        if CONFIG.additionally_include_next_size_nonlinear_ops_for_integers {
                            vec![
                                (IntegerOp::UDiv, sz * 2),
                                (IntegerOp::URem, sz * 2),
                                (IntegerOp::Mult, sz * 2),
                            ]
                        } else {
                            vec![]
                        },
                    )
                    .collect()
            };
            true
        }
        CType::BuiltIn(t @ (BuiltIn::Float | BuiltIn::Double | BuiltIn::LongDouble)) => {
            let sz = match t {
                BuiltIn::Float => 4,
                BuiltIn::Double => 8,
                BuiltIn::LongDouble => 16, // XXX: Is this reasonable?
                _ => unreachable!(),
            };
            set_upper_and_copy_size(this, sz);
            if matches!(t, BuiltIn::LongDouble) {
                // 80- and 96-bit "long double"s are quite common
                this.copy_sizes.extend([10, 12]);
                // We don't update upper bound size because it is set to 16 already.
            }
            this.zero_comparable = true;
            // TODO: Is this actually zero-comparable? Why do we even have zero-comparable
            // around anymore?
            this.float_ops = FloatOp::all_ops().into_iter().map(|o| (o, sz)).collect();
            if matches!(t, BuiltIn::LongDouble) {
                // 80- and 96-bit "long double"s are quite common
                for shorter_sz in [10, 12] {
                    this.float_ops
                        .extend(FloatOp::all_ops().into_iter().map(|o| (o, shorter_sz)));
                }
            }
            true
        }
        CType::Union(u) => {
            if u.iter().all(|t| completed.contains(t)) {
                for t in u {
                    let t_idx = *stypes.type_map.get(t).unwrap();
                    let t_idx = stypes.types.clone_at(t_idx);
                    structural::with_FORCE_CLONE_AND_JOIN_INSTEAD_OF_DIRECT_SCHEDULE_set(|| {
                        structural::with_FORCE_UPPER_BOUND_TO_BE_MAX_INSTEAD_OF_MIN_WHEN_JOINING_set(
                            || {
                                // Actually perform the join
                                stypes.types.join(this_idx, t_idx);
                            },
                        );
                    });
                }
                true
            } else {
                false
            }
        }
        CType::TypeDef(t) => {
            if completed.contains(t) {
                let ti = *stypes
                    .type_map
                    .get(t)
                    .expect("Completed types should exist in map");
                stypes.types.join(ti, this_idx);
                return true; // Early return
            } else {
                false
            }
        }
        CType::Struct(s) => {
            // Note: It _is_ feasible to relax this `completed` constraint a little (specifically,
            // only the head needs to be complete; the colocated members only need to be named to be
            // able to successfully complete a struct). However, we do not do this for now, opting
            // instead to expect a full completion.
            if s.iter().map(|(_, t)| t).all(|t| completed.contains(t)) {
                if s.len() == 0 {
                    this.set_upper_bound_size(0);
                } else if s.iter().all(|(_offs, t)| {
                    is_undefined_padding(&stypes.types[*stypes.type_map.get(t).unwrap()])
                }) {
                    // If the entire struct is filled with `undefined`s, then the struct is just a
                    // massive non-struct variable that has a big size.
                    //
                    // XXX: Or should we interpret this as a struct even then?
                    //
                    // Note: we are forced to reborrow `this` because otherwise it is a
                    // mut-shared-mut pattern.
                    stypes.types[this_idx].set_upper_bound_size(s.last().unwrap().0 + 1);
                } else {
                    let s0_typ = stypes.types[*stypes.type_map.get(&s[0].1).unwrap()].clone();
                    // Note: we are forced to reborrow `this` because otherwise it is a
                    // mut-shared-mut pattern.
                    stypes.types[this_idx] = s0_typ;
                    let size = if let Some(sz) = stypes.types[this_idx].observed_size() {
                        sz
                    } else {
                        // Unable to obtain a max type size, defer.
                        return false;
                    };
                    for (offs, t) in &s[1..] {
                        let ti = *stypes.type_map.get(t).unwrap();
                        if !is_undefined_padding(&stypes.types[ti]) {
                            if *offs == 0 {
                                trace!("Likely bitfield in 0th offset"; "name" => name, "s" => ?s);
                            } else {
                                stypes.types[this_idx]
                                    .colocated_struct_fields
                                    .insert((*offs).try_into().unwrap(), ti);
                            }
                        }
                    }
                    stypes.types[this_idx].set_upper_bound_size(size);
                }
                true
            } else {
                false
            }
        }
        CType::FixedSizeArray(elem, elemsize, size) => {
            if completed.contains(elem) {
                if *size == 0 {
                    this.set_upper_bound_size(0);
                } else {
                    let elem_idx = *stypes.type_map.get(elem).unwrap();
                    // Note: we are forced to reborrow `this` because otherwise it is a
                    // mut-shared-mut pattern.
                    stypes.types[this_idx] = stypes.types[elem_idx].clone();
                    for i in 1..*size {
                        let offset = elemsize * i;
                        stypes.types[this_idx]
                            .colocated_struct_fields
                            .insert(offset.try_into().expect("i > 0, elemsize > 0"), elem_idx);
                    }
                }
                true
            } else {
                false
            }
        }
        CType::UnsizedArray(_t) => {
            todo!("Trying to convert unsized arrays");
        }
        CType::Enum(sz, _e) => {
            this.set_upper_bound_size(*sz);
            // We don't insert smaller sizes for copying, since enums should not be split when
            // reading
            this.copy_sizes.insert(*sz);
            // XXX: For now, we are ignoring the values within the enumeration, except for zero,
            // simply because we have a zero_comparable, but see other comment regarding
            // zero_comparable.
            if _e.contains(&0) {
                this.zero_comparable = true;
            }
            this.integer_ops = [IntegerOp::Eq, IntegerOp::Neq]
                .into_iter()
                .map(|o| (o, 1))
                .collect();
            true
        }
        CType::Pointer(sz, t) => {
            this.set_upper_bound_size(*sz);
            this.copy_sizes.insert(*sz);
            this.zero_comparable = true;
            if let Some(&ti) = stypes.type_map.get(t) {
                this.pointer_to = Some(ti);
                this.integer_ops = IntegerOp::all_pointer_ops()
                    .into_iter()
                    .map(|o| (o, *sz))
                    .collect();
                true
            } else {
                false
            }
        }
        CType::Code => {
            this.observed_code = true;
            true
        }
    };
    if is_undefined_padding(&stypes.types[this_idx]) {
        // Ensure that `undefined` is the only type that can be marked as undefined. Required
        // for the correct generation of `CType::Struct`.
        assert!(
            matches!(ctype, CType::BuiltIn(BuiltIn::Undefined)),
            "For {:?}, {:?} is not undefined even though {:?} is undefined padding.",
            name,
            ctype,
            stypes.types[this_idx]
        );
    }
    success
}

#[derive(Debug)]
/// A collection of [`CType`]s
pub struct CTypes {
    pub ctypes: UnorderedMap<String, CType>,
}

impl CTypes {
    /// Convert c-like types to structural types
    pub fn to_structural(&self) -> STypes {
        let mut res = STypes {
            type_map: Default::default(),
            types: Container::new(),
        };

        let mut postponed_count: UnorderedMap<String, u64> = Default::default();

        let mut completed: UnorderedSet<String> = Default::default();
        let mut queue: VecDeque<_> = self.ctypes.iter().collect();
        while let Some((tn, ct)) = queue.pop_front() {
            if update_structural(ct, tn, &mut res, &completed) {
                // updated
                completed.insert(tn.to_owned());
            } else {
                // postponed till others are updated
                if let Some(count) = postponed_count.get_mut(tn) {
                    *count += 1;
                    // This is just a fallback in the (hopefully never) case of getting into an
                    // infinite loop; this way, we'll at least catch it, and report it.
                    assert!(
                        *count < 10000,
                        "Extremely unexpected number of postponements; ctypes must be broken"
                    );
                } else {
                    postponed_count.insert(tn.to_owned(), 1);
                }
                queue.push_back((tn, ct));
            }
        }

        res
    }
}

/// Get structural types equivalent to all primitive C types. Note that this also includes `code`
/// and the `undefined`s, but does not include `void` or `wchar_t`
///
/// If type rounding is not allowed on `upper_bound_size`, then the upper-bound-size-only
/// `undefined` is also skipped here (but the copy-sized undefineds, i.e., `undefined1`,
/// `undefined2`, ..., are kept).
pub fn structural_types_for_all_primitive_c_types() -> UnorderedMap<String, StructuralType> {
    let builtins = CTypes {
        ctypes: BuiltIn::all_builtins()
            .into_iter()
            .map(|b| (format!("{:?}", b), CType::BuiltIn(b)))
            .chain(std::iter::once((
                "VoidPtr".into(),
                // XXX: Pointer size
                CType::Pointer(8, "Void".into()),
            )))
            .collect(),
    };
    let structural = builtins.to_structural();
    structural
        .type_map
        .into_iter()
        .map(|(name, idx)| (name, structural.types[idx].clone()))
        .chain(std::iter::once((
            "Code".into(),
            StructuralType {
                observed_code: true,
                ..StructuralType::default()
            },
        )))
        .filter(|(name, _)| name != "Void" && name != "WCharT")
        .filter(|(name, _)| {
            if CONFIG.allow_type_rounding_based_on_upper_bound_size {
                true
            } else {
                name != "Undefined"
            }
        })
        .collect()
}

/// Map from C primitives to their sign-ignored (i.e., sign-normalized) primitive
pub fn sign_normalized_c_primitives() -> UnorderedMap<String, String> {
    let map: UnorderedMap<&str, &str> = [
        ("Bool", "Bool"),
        ("Char", "Char"),
        ("Code", "Code"),
        ("Double", "Double"),
        ("Float", "Float"),
        ("Int", "Int"),
        ("Long", "Long"),
        ("LongDouble", "LongDouble"),
        ("SInt128", "SInt128"),
        ("SInt256", "SInt256"),
        ("Short", "Short"),
        ("ShortShort", "ShortShort"),
        ("UChar", "Char"),
        ("UInt128", "Int128"),
        ("UInt256", "Int256"),
        ("ULong", "Long"),
        ("UShort", "Short"),
        ("UShortShort", "ShortShort"),
        ("Uint", "Int"),
        ("Undefined", "Undefined"),
        ("Undefined1", "Undefined1"),
        ("Undefined2", "Undefined2"),
        ("Undefined4", "Undefined4"),
        ("Undefined8", "Undefined8"),
        ("VoidPtr", "VoidPtr"),
    ]
    .into_iter()
    .collect();

    let c_types: Vec<_> = structural_types_for_all_primitive_c_types()
        .keys()
        .cloned()
        .collect();

    assert_eq!(map.len(), c_types.len());

    c_types
        .into_iter()
        .map(|t| {
            let nt = map.get(t.as_str()).unwrap().to_string();
            (t, nt)
        })
        .collect()
}
