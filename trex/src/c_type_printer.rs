//! Printable representation of C-like types, from structural types.

use crate::c_types::{self, BuiltIn, CType};
use crate::containers::unordered::{UnorderedMap, UnorderedSet};
use crate::joinable_container::{Container, Index, IndexMap};
use crate::log::*;
use crate::serialize_structural::SerializableStructuralTypes;
use crate::structural::StructuralType;
use crate::type_rounding::{self, RoundedIdx};
use std::collections::{BTreeSet, VecDeque};

/// A printable C-like type representation for structural types.
#[derive(Debug)]
pub struct PrintableCTypes<'a, ExtVar>
where
    ExtVar: std::hash::Hash + Ord + Eq,
{
    /// Map of variables to indices
    varmap: UnorderedMap<ExtVar, Index>,
    /// Map of indices to external type names
    external_type_name: IndexMap<String>,
    /// Map from unions to external type names; used for de-duplicating unions.
    union_name: UnorderedMap<BTreeSet<String>, String>,
    /// Map from external type names to c types; only used for non-builtins
    ctypes: UnorderedMap<String, CType>,
    /// The structural types used to get the printable C types
    structural_types: &'a Container<StructuralType>,
    /// Source of freshness, for creating type names
    type_name_stream: TypeNameStream,
    /// Rounded types, found via [`type_rounding`]
    rounded_types: IndexMap<UnorderedSet<RoundedTypeUnionMember>>,
}

impl<'a, ExtVar> PrintableCTypes<'a, ExtVar>
where
    ExtVar: std::hash::Hash + Ord + Eq + std::fmt::Display + Clone,
{
    /// Obtain printable C types from serializable structural types
    pub fn new(stypes: &'a SerializableStructuralTypes<ExtVar>) -> Self {
        let mut ret = Self {
            varmap: Default::default(),
            external_type_name: Default::default(),
            union_name: Default::default(),
            ctypes: Default::default(),
            structural_types: stypes.types(),
            type_name_stream: TypeNameStream::new(),
            rounded_types: Default::default(),
        };
        for (var, idx) in stypes.var_type_iter() {
            ret.varmap.insert(var.clone(), idx);
        }

        let (c_types_names, c_types): (Vec<_>, Vec<_>) =
            c_types::structural_types_for_all_primitive_c_types()
                .into_iter()
                .unzip();

        let rounding = type_rounding::round_up(ret.structural_types, &c_types, &c_types_names);
        for (idx, (_stype, hm)) in rounding.into_iter() {
            ret.rounded_types.insert(
                idx,
                hm.into_iter().map(RoundedTypeUnionMember::from).collect(),
            );
        }

        for (_var, idx) in stypes.var_type_iter() {
            let _ = ret.external_type_name_at(idx);
        }

        ret
    }

    /// Get the external type name for an index
    pub fn ext_type_name_at(&self, idx: Index) -> String {
        let idx = self.structural_types.get_canonical_index(idx);
        self.external_type_name.get(idx).unwrap().to_string()
    }

    /// Internal only. Returns the external type name for the the type at the index `idx`. If the
    /// type has not been set up already, sets it up before returning. Otherwise, leaves `self`
    /// unchanged.
    fn external_type_name_at(&mut self, idx: Index) -> String {
        let idx = self.structural_types.get_canonical_index(idx);
        if let Some(name) = self.external_type_name.get(idx) {
            return name.into();
        }

        let this = self.structural_types.get(idx);
        if (!this.colocated_struct_fields.is_empty()
            && !self.structural_types.index_eq(
                *this.colocated_struct_fields.last_key_value().unwrap().1,
                idx,
            ))
            || self.rounded_types.get(idx).unwrap().len() > 1
        {
            // We insert the name early on to bottom out recursion
            let this_name = self.type_name_stream.new_name();
            self.external_type_name.insert(idx, this_name);
        }

        // For situations where a type points back at itself, we need to potentially be concerned
        // about infinite recursion, so we handle the various cases that might show up.
        let mut forced_void_pointee = false;
        let mut self_referrential_pointee = false;
        if let Some(pointee) = this.pointer_to {
            if self.structural_types.index_eq(pointee, idx) {
                self_referrential_pointee = true;
                if this.colocated_struct_fields.is_empty() {
                    // Plain old type
                    if self.rounded_types.get(idx).unwrap().len() == 0 {
                        unreachable!("Can't round to nothing if there is a pointer")
                    } else if self.rounded_types.get(idx).unwrap().len() == 1 {
                        debug!("Infinitely recursing pointer with nothing else to it. Setting to `void*`");
                        forced_void_pointee = true;
                    } else {
                        // We will bottom out this recursion, since the name is inserted early.
                    }
                } else if self.structural_types.index_eq(
                    *this.colocated_struct_fields.last_key_value().unwrap().1,
                    idx,
                ) {
                    // The first field is pointing back to the struct itself, but then last field
                    // causes things to wrap up into an unsized array.
                    //
                    // In this case, we know for sure that there is a new struct name that will show
                    // up, so we can reasonably just insert the new name that will be used, to force
                    // a bottom-out to the recursion.
                    debug!("Pointer + unsized array situation, inserting new name");
                    let this_name = self.type_name_stream.new_name();
                    self.external_type_name.insert(idx, this_name);
                } else {
                    // We will bottom out this recursion, since the name is inserted early.
                }
            } else {
                // No issues, carry on!
            }
        }

        let pointee: Option<String> = if forced_void_pointee {
            Some("void".to_owned())
        } else {
            this.pointer_to.map(|idx| self.external_type_name_at(idx))
        };

        let rounded = self.rounded_types.get(idx).unwrap();
        let head_name = if rounded.len() == 0 {
            "void".to_owned()
        } else if rounded.len() == 1 {
            rounded.iter().next().unwrap().to_external(&pointee)
        } else {
            // union
            let union_members: BTreeSet<_> = rounded
                .into_iter()
                .map(|rtum| rtum.to_external(&pointee))
                .collect();
            let this_name = self
                .union_name
                .entry(union_members.clone())
                .or_insert(if self_referrential_pointee {
                    self.external_type_name.get(idx).unwrap().clone()
                } else {
                    self.type_name_stream.new_name()
                })
                .clone();
            self.ctypes.insert(
                this_name.clone(),
                CType::Union(union_members.into_iter().collect()),
            );
            this_name
        };

        if this.colocated_struct_fields.is_empty() {
            if this.observed_array {
                let this_name = format!("{head_name}[]");
                self.ctypes
                    .insert(this_name.clone(), CType::UnsizedArray(head_name));
                self.external_type_name.insert(idx, this_name.clone());
                this_name
            } else {
                // plain old type
                self.external_type_name.insert(idx, head_name.clone());
                head_name
            }
        } else {
            // struct
            if self.structural_types.index_eq(
                *this.colocated_struct_fields.last_key_value().unwrap().1,
                idx,
            ) {
                // Last field is the same as the struct, so it is an unsized array
                if this.colocated_struct_fields.len() == 1 {
                    // There are no other fields, so this is a "simple" unsized array
                    let this_name = format!("{head_name}[]");
                    self.ctypes
                        .insert(this_name.clone(), CType::UnsizedArray(head_name.clone()));
                    self.external_type_name.insert(idx, this_name.clone());
                    this_name
                } else {
                    // We need to set up a struct for all field elements except the last, and _then_
                    // set up the unsized array.
                    //
                    // We pick up an existing "new name" if it has been set up already (for example,
                    // to bottom-out recursions), or create a new one if needed.
                    let new_name = self
                        .external_type_name
                        .get(idx)
                        .cloned()
                        .unwrap_or_else(|| self.type_name_stream.new_name());
                    let this_name = format!("{new_name}[]");
                    self.ctypes
                        .insert(this_name.clone(), CType::UnsizedArray(new_name.clone()));
                    self.external_type_name.insert(idx, this_name.clone());
                    if this.observed_array {
                        debug!(
                            "Received an array marker on first field of struct. Ignoring.";
                            "ctype" => %this_name,
                            "stype" => ?this,
                            "idx" => ?idx,
                        );
                    }
                    let new_struct_colocated_offsets: Vec<_> = this
                        .colocated_struct_fields
                        .iter()
                        .filter(|(_field_pos, field_idx)| {
                            !self.structural_types.index_eq(idx, **field_idx)
                        })
                        .collect();
                    let new_struct_fields = std::iter::once((0, head_name))
                        .chain(new_struct_colocated_offsets.into_iter().map(
                            |(field_pos, field_idx)| {
                                (field_pos.get(), self.external_type_name_at(*field_idx))
                            },
                        ))
                        .collect::<Vec<(usize, String)>>();
                    let new_struct_type = CType::Struct(new_struct_fields);
                    self.ctypes.insert(new_name.clone(), new_struct_type);
                    this_name
                }
            } else {
                // Plaid old struct
                let this_name = self.external_type_name.get(idx).unwrap().clone();
                let struct_fields = std::iter::once((0, head_name))
                    .chain(
                        this.colocated_struct_fields
                            .iter()
                            .map(|(field_pos, field_idx)| {
                                (field_pos.get(), self.external_type_name_at(*field_idx))
                            }),
                    )
                    .collect::<Vec<(usize, String)>>();
                if this.observed_array {
                    debug!(
                        "Received an array marker on first field of struct. Ignoring.";
                        "ctype" => %this_name,
                        "stype" => ?this,
                        "idx" => ?idx,
                    );
                }
                let c_struct_type = CType::Struct(struct_fields);
                self.ctypes.insert(this_name.clone(), c_struct_type);
                this_name
            }
        }
    }
}

impl<'a, ExtVar> std::fmt::Display for PrintableCTypes<'a, ExtVar>
where
    ExtVar: std::hash::Hash + Ord + Eq + std::fmt::Display + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for (var, idx) in self.varmap.iter() {
            let idx = self.structural_types.get_canonical_index(*idx);
            let exttype = self.external_type_name.get(idx).unwrap();
            writeln!(f, "// {var} : {exttype}")?;
        }
        let mut printed: UnorderedSet<String> = Default::default();
        let mut queue: VecDeque<String> = self
            .external_type_name
            .iter()
            .map(|(_idx, idx)| idx)
            .cloned()
            .collect();
        while let Some(typ) = queue.pop_front() {
            if !printed.insert(typ.clone()) {
                // Printed already
                continue;
            }
            if let Some(ctyp) = self.ctypes.get(&typ) {
                match ctyp {
                    CType::Struct(fields) => {
                        writeln!(f)?;
                        writeln!(f, "struct {typ} {{")?;
                        for (posn, fieldtyp) in fields {
                            writeln!(f, "  {fieldtyp} field_{posn};")?;
                            queue.push_back(fieldtyp.clone());
                        }
                        writeln!(f, "}};")?;
                    }
                    CType::Union(members) => {
                        writeln!(f)?;
                        writeln!(f, "union {typ} {{")?;
                        for (i, member) in members.iter().enumerate() {
                            writeln!(f, "  {member} alt_{i};")?;
                            queue.push_back(member.clone());
                        }
                        writeln!(f, "}};")?;
                    }
                    CType::UnsizedArray(elem) => {
                        queue.push_back(elem.clone());
                    }
                    _ => unreachable!("{:?}", ctyp),
                }
            }
        }
        Ok(())
    }
}

impl<'a, ExtVar> PrintableCTypes<'a, ExtVar>
where
    ExtVar: std::hash::Hash + Ord + Eq + std::fmt::Display + Clone,
{
    fn internal_formatted_types_for(
        &self,
        typ: &str,
        visited: &mut UnorderedSet<String>,
        fuel: usize,
        separated_unions: bool,
    ) -> Vec<String> {
        use std::fmt::Write;
        if fuel == 0 {
            // Prevent infinite recursion
            return vec!["out-of-fuel".into()];
        }
        if !visited.insert(typ.to_string()) {
            // Printed already
            return vec![];
        }
        if let Some(ctyp) = self.ctypes.get(typ) {
            match ctyp {
                CType::Struct(fields) => {
                    let mut res = String::new();
                    let mut multipliers = vec![];
                    writeln!(res, "struct {typ} {{").unwrap();
                    for (posn, fieldtyp) in fields {
                        writeln!(res, "  {fieldtyp} field_{posn};").unwrap();
                        multipliers.push(self.internal_formatted_types_for(
                            &fieldtyp,
                            visited,
                            fuel - 1,
                            separated_unions,
                        ));
                    }
                    writeln!(res, "}};").unwrap();
                    writeln!(res).unwrap();
                    let mut res = vec![res];
                    for v in multipliers {
                        let old_res = std::mem::replace(&mut res, vec![]);
                        let v = if v.is_empty() { vec!["".into()] } else { v };
                        for x in v {
                            for r in &old_res {
                                res.push(format!("{}{}", r, x));
                            }
                        }
                    }
                    res
                }
                CType::Union(members) if separated_unions => {
                    let mut res = vec![];
                    for member in members {
                        let member = if member.starts_with(typ)
                            && member.ends_with('*')
                            && member.len()
                                == typ.len() + member.chars().filter(|&c| c == '*').count()
                        {
                            // This is a pointer to the type, so we replace it with a `void*` here.
                            "void*"
                        } else {
                            member
                        };
                        let mem = self.internal_formatted_types_for(
                            member,
                            &mut visited.clone(),
                            fuel - 1,
                            separated_unions,
                        );
                        if mem.is_empty() {
                            res.push(member.to_string());
                        } else {
                            res.extend(mem);
                        }
                    }
                    res
                }
                CType::Union(members) => {
                    let mut res = String::new();
                    let mut multipliers = vec![];
                    writeln!(res, "union {typ} {{").unwrap();
                    for (i, member) in members.iter().enumerate() {
                        writeln!(res, "  {member} alt_{i};").unwrap();
                        multipliers.push(self.internal_formatted_types_for(
                            &member,
                            visited,
                            fuel - 1,
                            separated_unions,
                        ));
                    }
                    writeln!(res, "}};").unwrap();
                    writeln!(res).unwrap();
                    let mut res = vec![res];
                    for v in multipliers {
                        let old_res = std::mem::replace(&mut res, vec![]);
                        let v = if v.is_empty() { vec!["".into()] } else { v };
                        for x in v {
                            for r in &old_res {
                                res.push(format!("{}{}", r, x));
                            }
                        }
                    }
                    res
                }
                CType::UnsizedArray(elem) => {
                    let mut res = String::new();
                    writeln!(res, "{elem}").unwrap();
                    let mut res = vec![res];
                    let old_res = std::mem::replace(&mut res, vec![]);
                    let v = self.internal_formatted_types_for(
                        elem,
                        visited,
                        fuel - 1,
                        separated_unions,
                    );
                    let v = if v.is_empty() { vec!["".into()] } else { v };
                    for x in v {
                        for r in &old_res {
                            res.push(format!("{}{}", r, x));
                        }
                    }
                    res
                }
                _ => unreachable!("{:?}", ctyp),
            }
        } else if typ.ends_with('*') {
            let mut res = typ.to_string();
            writeln!(res).unwrap();
            let mut res = vec![res];
            let v = self.internal_formatted_types_for(
                typ.trim_end_matches('*').trim_end(),
                visited,
                fuel - 1,
                separated_unions,
            );
            let old_res = std::mem::replace(&mut res, vec![]);
            let v = if v.is_empty() { vec!["".into()] } else { v };
            for x in v {
                for r in &old_res {
                    res.push(format!("{}{}", r, x));
                }
            }
            res
        } else if typ.ends_with(']') {
            let mut res = typ.to_string();
            writeln!(res).unwrap();
            let mut res = vec![res];
            let elem = &typ[0..typ.rfind('[').unwrap()];
            let v = self.internal_formatted_types_for(elem, visited, fuel - 1, separated_unions);
            let old_res = std::mem::replace(&mut res, vec![]);
            let v = if v.is_empty() { vec!["".into()] } else { v };
            for x in v {
                for r in &old_res {
                    res.push(format!("{}{}", r, x));
                }
            }
            res
        } else {
            // No need to expand out
            vec![]
        }
    }

    pub fn formatted_types_for(&self, type_name: &str, separated_unions: bool) -> Vec<String> {
        let res = self.internal_formatted_types_for(
            type_name,
            &mut UnorderedSet::new(),
            100,
            separated_unions,
        );
        if res.is_empty() {
            // This should only be reached for primitives
            assert!(
                type_name == "code"
                    || BuiltIn::all_builtins()
                        .into_iter()
                        .any(|x| x.to_printable() == type_name),
                "Only builtins should reach this branch, got {}",
                type_name
            );
            vec![type_name.into()]
        } else {
            if !separated_unions {
                assert_eq!(
                    res.len(),
                    1,
                    "Expected only one element for {type_name}, got {:?}",
                    res
                );
            }
            if res.iter().any(|x| x.contains("out-of-fuel")) {
                panic!(
                    "Infinite recursion detected for type {}.  See {:?}",
                    type_name, res
                );
            }
            res
        }
    }
}

/// Rounded type union member
#[derive(PartialEq, Eq, Hash, Clone, Debug, PartialOrd, Ord)]
enum RoundedTypeUnionMember {
    Primitive(String),
    Pointer,
    Code,
    Padding(usize),
}
impl RoundedTypeUnionMember {
    fn to_external(&self, pointee: &Option<String>) -> String {
        if matches!(self, Self::Pointer) {
            assert!(pointee.is_some());
        }
        match self {
            Self::Primitive(nm) => nm.clone(),
            Self::Pointer => format!("{}*", pointee.as_ref().unwrap()),
            Self::Code => "code".to_owned(),
            Self::Padding(sz) => format!("padding[{sz}]"),
        }
    }
}
impl<'a> From<RoundedIdx<'a>> for RoundedTypeUnionMember {
    fn from(x: RoundedIdx<'a>) -> Self {
        match x {
            RoundedIdx::Primitive(_, "Code") => RoundedTypeUnionMember::Code,
            RoundedIdx::Primitive(_, "VoidPtr") => RoundedTypeUnionMember::Pointer,
            RoundedIdx::Primitive(_, name) => RoundedTypeUnionMember::Primitive(
                BuiltIn::all_builtins()
                    .into_iter()
                    .find(|x| &format!("{:?}", x) == name)
                    .unwrap()
                    .to_printable()
                    .to_owned(),
            ),
            RoundedIdx::Padding(sz) => RoundedTypeUnionMember::Padding(sz),
        }
    }
}

/// A source of fresh type names. Names are only guaranteed to be unique within the particular
/// stream (i.e., different streams may produce same names, but the same stream will always produce
/// different names, each time a new one is asked for).
#[derive(Debug)]
struct TypeNameStream {
    prefix: String,
    counter: u64,
}

impl TypeNameStream {
    /// New source
    fn new() -> Self {
        Self {
            prefix: "t".into(),
            counter: 0,
        }
    }

    /// Generate a new type name
    fn new_name(&mut self) -> String {
        self.counter += 1;
        format!("{}{}", self.prefix, self.counter)
    }
}

#[cfg(test)]
mod test {
    #[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone)]
    pub struct Var(String);
    impl Var {
        pub fn inner(&self) -> &str {
            &self.0
        }
    }
    impl From<String> for Var {
        fn from(s: String) -> Self {
            Self(s)
        }
    }
    impl std::fmt::Display for Var {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            assert!(!self.0.contains('\t'));
            write!(f, "{}", self.0)
        }
    }
    impl crate::serialize_structural::Parseable for Var {
        fn parse_from(s: &str) -> Option<Self> {
            if s.contains('\t') {
                None
            } else {
                Some(Self(s.to_owned()))
            }
        }
    }

    #[test]
    fn printable_c_type_for_struct_with_union_in_first_field() {
        use crate::serialize_structural::{Parseable, SerializableStructuralTypes};

        let st =
            "VAR_MAP\n\tx\tt1\n\nSTRUCTURAL_TYPES\n\tt1\n\t\tUPPER_BOUND_SIZE\t8\n\t\tCOPY_SIZES\t{1, 8}\n\t\tPOINTER_TO\tu4\n\t\tCOLOCATED_STRUCT_FIELDS\t8\tu4\n\n\tu4\n\t\tUPPER_BOUND_SIZE\t4\n\n\n";
        let expected =
            "// x : t1\n\nstruct t1 {\n  t2 field_0;\n  undefined4 field_8;\n};\n\nunion t2 {\n  undefined1 alt_0;\n  undefined4* alt_1;\n};\n";

        let sst: SerializableStructuralTypes<Var> =
            SerializableStructuralTypes::parse_from(st).unwrap();
        let pct = crate::c_type_printer::PrintableCTypes::new(&sst);
        eprintln!("\nExpected:\n{}\n", expected);
        eprintln!("\nGot:\n{}\n", pct.to_string());
        assert_eq!(pct.to_string(), expected);
    }

    #[test]
    fn printable_c_type_for_self_referential_pointer_to_union() {
        use crate::serialize_structural::{Parseable, SerializableStructuralTypes};

        let st = "VAR_MAP\n\tx\tt1\n\nSTRUCTURAL_TYPES\n\tt1\n\t\tUPPER_BOUND_SIZE\t8\n\t\tCOPY_SIZES\t{8}\n\t\tPOINTER_TO\tt1\n\t\tINTEGER_OPS\t{Xor_4}\n\n";
        let expected = "// x : t1\n\nunion t1 {\n  int32_t alt_0;\n  t1* alt_1;\n};\n";

        let sst: SerializableStructuralTypes<Var> =
            SerializableStructuralTypes::parse_from(st).unwrap();
        let pct = crate::c_type_printer::PrintableCTypes::new(&sst);
        eprintln!("\nExpected:\n{}\n", expected);
        eprintln!("\nGot:\n{}\n", pct.to_string());
        assert_eq!(pct.to_string(), expected);
    }
}
